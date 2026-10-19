package credentials

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The test server's certificate is valid for example.com.
const credentialsYAML = `
servers:
  - host: example.com
    replacements:
      - { header: Authorization, placeholder: PLACEHOLDER_TOKEN, value: real-token }
      - { header: Cookie, placeholder: PLACEHOLDER_SESSION, value: real-session }
`

func TestCredentialsAreReplaced(t *testing.T) {
	server := startTestServer(t)
	client, _ := startInterceptingProxy(t, server, true)

	request, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	request.Header.Set("Authorization", "Bearer PLACEHOLDER_TOKEN")
	request.Header.Set("Cookie", "theme=dark; session=PLACEHOLDER_SESSION")
	request.Header.Set("X-Other", "PLACEHOLDER_TOKEN")
	request.Header["User-Agent"] = []string{""} // no User-Agent
	want := "authorization=Bearer real-token cookie=theme=dark; session=real-session x-other=PLACEHOLDER_TOKEN user-agent=[] body="
	if got := send(t, client, request); got != want {
		t.Errorf("server got %q, want %q", got, want)
	}
}

func TestRequestsOnOneConnection(t *testing.T) {
	server := startTestServer(t)
	client, accepted := startInterceptingProxy(t, server, true)

	for i := range 3 {
		body := fmt.Sprintf("request %d", i)
		request, _ := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader(body))
		request.Header.Set("Authorization", "PLACEHOLDER_TOKEN")
		request.Header.Set("Expect", "100-continue") // the client waits up to 10 seconds for "100 Continue"
		start := time.Now()
		got := send(t, client, request)
		if !strings.HasPrefix(got, "authorization=real-token ") || !strings.HasSuffix(got, "body="+body) {
			t.Errorf("server got %q, want the real token and the body %q", got, body)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("request took %v: the client did not get 100 Continue", elapsed)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Errorf("proxy accepted %d connections, want 1", got)
	}
}

func TestUntrustedServerGetsNoRequest(t *testing.T) {
	server := startTestServer(t)
	client, _ := startInterceptingProxy(t, server, false)

	response, err := client.Get("https://example.com/")
	if err == nil {
		response.Body.Close()
		t.Fatal("request succeeded, want it to fail as the server's certificate is not trusted")
	}
	if got := server.requests.Load(); got != 0 {
		t.Errorf("server got %d requests, want none", got)
	}
}

func TestSwitchingProtocols(t *testing.T) {
	server := startTestServer(t)
	_, proxy := startInterceptingProxyAddress(t, server, true)

	conn, err := tls.Dial("tcp", proxy, &tls.Config{ServerName: "example.com", RootCAs: server.interceptionCAs})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("got status %s, want 101", response.Status)
	}
	io.WriteString(conn, "ping\n")
	if line, _ := reader.ReadString('\n'); line != "echo: ping\n" {
		t.Errorf("got %q after the protocol switch, want %q", line, "echo: ping\n")
	}
}

// testServer is an HTTPS server for example.com describing the requests it gets.
type testServer struct {
	*httptest.Server
	requests        atomic.Int32
	interceptionCAs *x509.CertPool // trusted by the clients
	credentialsYAML string
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	caCertificate, caKey := newTestCA(t, true)
	server := &testServer{
		interceptionCAs: x509.NewCertPool(),
		credentialsYAML: "caCertificate: |\n" + indent(caCertificate) + "caKey: |\n" + indent(caKey) + credentialsYAML,
	}
	server.interceptionCAs.AppendCertsFromPEM([]byte(caCertificate))
	server.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.requests.Add(1)
		if r.URL.Path == "/upgrade" {
			switchToEcho(w)
			return
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "authorization=%s cookie=%s x-other=%s user-agent=%v body=%s",
			r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Other"), r.Header["User-Agent"], body)
	}))
	t.Cleanup(server.Close)
	return server
}

// switchToEcho switches the connection to a protocol answering each line with "echo: " and the line.
func switchToEcho(w http.ResponseWriter) {
	conn, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	buffered.Flush()
	for {
		line, err := buffered.ReadString('\n')
		if err != nil {
			return
		}
		buffered.WriteString("echo: " + line)
		buffered.Flush()
	}
}

// startInterceptingProxy runs a proxy sending all connections to server and
// intercepting them. It returns an HTTP client using it, and the count of
// connections it accepted.
func startInterceptingProxy(t *testing.T, server *testServer, trustServer bool) (*http.Client, *atomic.Int32) {
	accepted, proxy := startInterceptingProxyAddress(t, server, trustServer)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
			},
			TLSClientConfig:       &tls.Config{RootCAs: server.interceptionCAs},
			ExpectContinueTimeout: 10 * time.Second,
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	return client, accepted
}

func startInterceptingProxyAddress(t *testing.T, server *testServer, trustServer bool) (*atomic.Int32, string) {
	t.Helper()
	injector, err := Parse([]byte(server.credentialsYAML))
	if err != nil {
		t.Fatal(err)
	}
	injector.RootCAs = x509.NewCertPool()
	if trustServer {
		injector.RootCAs.AddCert(server.Certificate())
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := &atomic.Int32{}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer client.Close()
				hello := ReadClientHello(client)
				if !injector.Intercepts(hello.ServerName, 443) {
					t.Errorf("connection to %q not intercepted", hello.ServerName)
					return
				}
				upstream, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					return
				}
				defer upstream.Close()
				injector.Intercept(slog.Default(), client, hello, upstream, upstream, 443)
			}()
		}
	}()
	return accepted, listener.Addr().String()
}

// send sends request with client, and returns the response body.
func send(t *testing.T, client *http.Client, request *http.Request) string {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
