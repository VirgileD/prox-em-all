package credentials

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// handshakeTimeout bounds each TLS handshake of an intercepted connection.
const handshakeTimeout = 10 * time.Second

// stats counts intercepted connections and replaced credentials. expvar
// publishes them under /debug/vars.
var stats = expvar.NewMap("credentials")

// Injector replaces placeholder credentials in the requests sent to the
// configured servers.
type Injector struct {
	// RootCAs verify the certificates of the servers. Nil means the system's roots.
	RootCAs *x509.CertPool

	servers      map[string]Server // by "host:port"
	ports        []uint16
	certificates *certificateMaker
}

func newInjector(ca tls.Certificate, servers map[string]Server) (*Injector, error) {
	certificates, err := newCertificateMaker(ca)
	if err != nil {
		return nil, err
	}
	injector := &Injector{servers: servers, certificates: certificates}
	for _, server := range servers {
		if !slices.Contains(injector.ports, server.Port) {
			injector.ports = append(injector.ports, server.Port)
		}
	}
	slices.Sort(injector.ports)
	return injector, nil
}

func serverAddress(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// Ports returns the ports of the configured servers.
func (i *Injector) Ports() []uint16 {
	return i.ports
}

// Hosts returns the names of the configured servers.
func (i *Injector) Hosts() []string {
	var hosts []string
	for _, server := range i.servers {
		hosts = append(hosts, server.Host)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// Intercepts reports whether the connections to serverName on port are intercepted.
func (i *Injector) Intercepts(serverName string, port uint16) bool {
	_, found := i.servers[serverAddress(serverName, port)]
	return found
}

// Intercept serves a client connection to a server it intercepts. It opens
// TLS with the server through upstream and checks its certificate, then ends
// the client's TLS with a certificate signed by the CA, and forwards the
// requests with their credentials replaced.
//
// The client's ClientHello was already read from client. Data from upstream is
// read from upstreamReader, which may already hold bytes received from it.
func (i *Injector) Intercept(log *slog.Logger, client net.Conn, hello ClientHello, upstream net.Conn, upstreamReader io.Reader, port uint16) {
	server := i.servers[serverAddress(hello.ServerName, port)]
	stats.Add("intercepted", 1)

	// The server's certificate is checked before the client can send any request.
	upstreamTLS := tls.Client(connWithReader{Conn: upstream, reader: upstreamReader}, &tls.Config{
		ServerName: server.Host,
		NextProtos: []string{"http/1.1"},
		RootCAs:    i.RootCAs,
	})
	if err := handshake(upstreamTLS); err != nil {
		log.Warn("TLS handshake with the server failed", "error", err)
		stats.Add("failed", 1)
		return
	}

	clientReader := io.MultiReader(bytes.NewReader(hello.Raw), client)
	clientTLS := tls.Server(connWithReader{Conn: client, reader: clientReader}, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return i.certificates.certificate(server.Host)
		},
		// HTTP/2 is not supported: clients fall back to HTTP/1.1.
		NextProtos: []string{"http/1.1"},
	})
	if err := handshake(clientTLS); err != nil {
		log.Warn("TLS handshake with the client failed, does it trust the CA?", "error", err)
		stats.Add("failed", 1)
		return
	}
	log.Debug("intercepted connection")
	forwardRequests(log, clientTLS, upstreamTLS, server.Replacements)
}

func handshake(conn *tls.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	return conn.HandshakeContext(ctx)
}

// forwardRequests forwards the client's requests to the server, with their
// credentials replaced, and the server's responses to the client, one request
// at a time.
func forwardRequests(log *slog.Logger, client, upstream *tls.Conn, replacements []Replacement) {
	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)
	for {
		request, err := http.ReadRequest(clientReader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warn("cannot read request from the client", "error", err)
			}
			return
		}
		if replaced := replaceCredentials(request.Header, replacements); len(replaced) > 0 {
			log.Debug("replaced credentials", "method", request.Method, "headers", replaced)
			stats.Add("replaced", 1)
		}
		// The request is forwarded whole, body included, so the proxy itself
		// tells the client to send the body.
		if strings.EqualFold(request.Header.Get("Expect"), "100-continue") {
			request.Header.Del("Expect")
			if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return
			}
		}
		// Request.Write adds a User-Agent header when there is none: keep it absent.
		if _, found := request.Header["User-Agent"]; !found {
			request.Header["User-Agent"] = []string{""}
		}
		if err := request.Write(upstream); err != nil {
			log.Warn("cannot send request to the server", "error", err)
			return
		}

		response, err := readFinalResponse(upstreamReader, request, client)
		if err != nil {
			log.Warn("cannot read response from the server", "error", err)
			return
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			// For instance a WebSocket: the connection no longer carries HTTP.
			relay(client, upstream, clientReader, upstreamReader)
			return
		}
		if err := response.Write(client); err != nil {
			log.Warn("cannot send response to the client", "error", err)
			return
		}
		if request.Close || response.Close {
			_ = client.CloseWrite()
			return
		}
	}
}

// replaceCredentials replaces the placeholders found in header, and returns
// the names of the headers changed.
func replaceCredentials(header http.Header, replacements []Replacement) []string {
	var replaced []string
	for _, replacement := range replacements {
		values := header[replacement.Header]
		for i, value := range values {
			if strings.Contains(value, replacement.Placeholder) {
				values[i] = strings.ReplaceAll(value, replacement.Placeholder, replacement.Value)
				replaced = append(replaced, replacement.Header)
			}
		}
	}
	return replaced
}

// readFinalResponse reads the server's response to request. Informational
// responses (1xx) coming first are sent to the client as they arrive. A
// "101 Switching Protocols" response is final, and is also sent to the client.
func readFinalResponse(upstream *bufio.Reader, request *http.Request, client io.Writer) (*http.Response, error) {
	for {
		response, err := http.ReadResponse(upstream, request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 200 {
			return response, nil
		}
		// Written by hand: Response.Write could add headers such as Content-Length.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "HTTP/%d.%d %s\r\n", response.ProtoMajor, response.ProtoMinor, response.Status)
		_ = response.Header.Write(&buf)
		buf.WriteString("\r\n")
		if _, err := client.Write(buf.Bytes()); err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			return response, nil
		}
	}
}

// relay copies data between client and upstream in both directions until both
// directions are done. Data is read from clientReader and upstreamReader,
// which may already hold data received from them.
func relay(client, upstream *tls.Conn, clientReader, upstreamReader io.Reader) {
	copyData := func(dst *tls.Conn, src io.Reader) {
		if _, err := io.Copy(dst, src); err != nil {
			// A broken connection ends the other direction too. Closing the
			// TCP connections, not the TLS ones, never waits for a stuck write.
			client.NetConn().Close()
			upstream.NetConn().Close()
			return
		}
		_ = dst.CloseWrite()
	}
	var wg sync.WaitGroup
	wg.Go(func() { copyData(upstream, clientReader) })
	wg.Go(func() { copyData(client, upstreamReader) })
	wg.Wait()
}

// connWithReader is a connection whose data is read from reader, which may
// hold bytes already read from the connection.
type connWithReader struct {
	net.Conn
	reader io.Reader
}

func (c connWithReader) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
