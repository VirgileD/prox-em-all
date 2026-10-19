package credentials

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

// clientHelloTimeout bounds the wait for a client's TLS ClientHello. A
// protocol where the server speaks first is forwarded after this delay.
const clientHelloTimeout = 5 * time.Second

// ClientHello is the start of a client connection, read to find which server
// the client asks for.
type ClientHello struct {
	// ServerName is the server name indication (SNI) of the ClientHello,
	// lowercased. It is empty when there is none or the data is not TLS.
	ServerName string

	// Raw holds the bytes read from the client, to forward before the rest of
	// the connection.
	Raw []byte
}

// errStopHandshake stops the TLS handshake once the ClientHello is read.
var errStopHandshake = errors.New("stop after the ClientHello")

// ReadClientHello reads the TLS ClientHello that client sends first.
func ReadClientHello(client net.Conn) ClientHello {
	recorder := &recordingConn{Conn: client}
	var serverName string
	// crypto/tls parses the ClientHello; the handshake stops right after.
	server := tls.Server(recorder, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = strings.ToLower(hello.ServerName)
			return nil, errStopHandshake
		},
	})
	_ = client.SetReadDeadline(time.Now().Add(clientHelloTimeout))
	_ = server.Handshake() // always fails: stopped, or not TLS
	_ = client.SetReadDeadline(time.Time{})
	return ClientHello{ServerName: serverName, Raw: recorder.recorded.Bytes()}
}

// recordingConn keeps a copy of the data read from a connection, and sends
// nothing to it, so that the client sees no TLS alert.
type recordingConn struct {
	net.Conn
	recorded bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.recorded.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
