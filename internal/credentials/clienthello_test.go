package credentials

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func TestReadClientHello(t *testing.T) {
	server := startTestServer(t)
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()
	handshakeDone := make(chan error, 1)
	go func() {
		client := tls.Client(clientConn, &tls.Config{ServerName: "EXAMPLE.com", RootCAs: server.interceptionCAs})
		handshakeDone <- client.Handshake()
	}()

	hello := ReadClientHello(proxyConn)
	if hello.ServerName != "example.com" {
		t.Errorf("got server name %q, want example.com", hello.ServerName)
	}

	// The bytes read are given back to a TLS server, as when intercepting.
	injector, err := Parse([]byte(server.credentialsYAML))
	if err != nil {
		t.Fatal(err)
	}
	replayed := connWithReader{Conn: proxyConn, reader: io.MultiReader(bytes.NewReader(hello.Raw), proxyConn)}
	tlsServer := tls.Server(replayed, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return injector.certificates.certificate("example.com")
		},
	})
	if err := tlsServer.Handshake(); err != nil {
		t.Fatalf("handshake after replaying the ClientHello: %v", err)
	}
	if err := <-handshakeDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
}

func TestReadClientHelloOfNonTLSData(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()
	data := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() {
		io.WriteString(clientConn, data)
		clientConn.Close()
	}()

	hello := ReadClientHello(proxyConn)
	if hello.ServerName != "" {
		t.Errorf("got server name %q, want none", hello.ServerName)
	}
	rest, _ := io.ReadAll(proxyConn)
	if got := string(hello.Raw) + string(rest); got != data {
		t.Errorf("got %q in total, want %q: bytes lost", got, data)
	}
}
