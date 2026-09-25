package tcpproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// handshakeTimeout bounds the time an upstream proxy takes to open a tunnel.
const handshakeTimeout = 10 * time.Second

// redirectError reports that an HTTP proxy answered with a redirection,
// typically to a login page.
type redirectError struct {
	status   string
	response []byte // the complete HTTP response
}

func (e *redirectError) Error() string {
	return "proxy answered " + e.status
}

// dialProxy opens a tunnel to target ("host:port") through an HTTP or SOCKS5
// proxy. Data from the tunnel must be read from the returned reader, which may
// already hold bytes an HTTP proxy sent right after its answer.
func (s *Server) dialProxy(proxy *url.URL, target, clientIP string) (*net.TCPConn, io.Reader, error) {
	conn, err := s.dialTCP(proxy.Host)
	if err != nil {
		return nil, nil, err
	}
	reader, err := handshake(conn, proxy, target, clientIP)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, reader, nil
}

// handshake asks the proxy to open a tunnel to target, within handshakeTimeout.
func handshake(conn *net.TCPConn, proxy *url.URL, target, clientIP string) (io.Reader, error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	var reader io.Reader = conn
	var err error
	if proxy.Scheme == "socks5" {
		err = socks5Connect(conn, proxy.User, target)
	} else {
		reader, err = httpConnect(conn, proxy.User, target, clientIP)
	}
	if err != nil {
		return nil, err
	}
	return reader, conn.SetDeadline(time.Time{})
}

// dialTCP connects to address with the server's dialer.
func (s *Server) dialTCP(address string) (*net.TCPConn, error) {
	conn, err := s.Dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil // always true for a "tcp" dial
}

// httpConnect asks an HTTP proxy to open a tunnel to target with the CONNECT
// method. It returns the reader the tunnel data must be read from.
func httpConnect(conn io.ReadWriter, user *url.Userinfo, target, clientIP string) (io.Reader, error) {
	request := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"X-Forwarded-For: " + clientIP + "\r\n"
	if user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		request += "Proxy-Authorization: Basic " + credentials + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("read answer to CONNECT: %w", err)
	}
	switch {
	case response.StatusCode == http.StatusOK:
		return reader, nil
	case response.StatusCode >= 300 && response.StatusCode < 400:
		var buf bytes.Buffer
		if err := response.Write(&buf); err != nil {
			return nil, fmt.Errorf("read redirection: %w", err)
		}
		return nil, &redirectError{status: response.Status, response: buf.Bytes()}
	default:
		return nil, fmt.Errorf("proxy answered %s", response.Status)
	}
}

// socks5Errors describes the error codes of SOCKS5 connection replies.
var socks5Errors = map[byte]string{
	1: "general failure",
	2: "connection not allowed by ruleset",
	3: "network unreachable",
	4: "host unreachable",
	5: "connection refused",
	6: "TTL expired",
	7: "command not supported",
	8: "address type not supported",
}

// socks5Connect asks a SOCKS5 proxy to connect to target (RFC 1928),
// authenticating with a username and a password (RFC 1929) when user is set.
func socks5Connect(conn io.ReadWriter, user *url.Userinfo, target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return err
	}

	// Greeting: protocol version 5, and the one authentication method offered.
	method := byte(0) // no authentication
	if user != nil {
		method = 2 // username and password
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	reply := make([]byte, 2) // version, chosen method
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != method {
		return errors.New("SOCKS5 proxy refused the authentication method")
	}

	if user != nil {
		username := user.Username()
		password, _ := user.Password()
		if len(username) > 255 || len(password) > 255 {
			return errors.New("SOCKS5 username and password are limited to 255 bytes")
		}
		// Authentication version 1, then the length-prefixed username and password.
		request := append([]byte{1, byte(len(username))}, username...)
		request = append(append(request, byte(len(password))), password...)
		if _, err := conn.Write(request); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply); err != nil { // version, status
			return err
		}
		if reply[1] != 0 {
			return errors.New("SOCKS5 proxy rejected the username or password")
		}
	}

	// Connection request: version 5, command CONNECT, reserved byte, then the
	// target as an IPv4 address (type 1) or a domain name (type 3), and its port.
	request := []byte{5, 1, 0}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		request = append(request, 1)
		request = append(request, addr.AsSlice()...)
	} else if len(host) <= 255 {
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	} else {
		return errors.New("SOCKS5 hostnames are limited to 255 bytes")
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return err
	}

	// Reply: version, status, reserved byte, then the address the proxy
	// connected from, which is read and ignored.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if status := header[1]; status != 0 {
		reason, known := socks5Errors[status]
		if !known {
			reason = fmt.Sprintf("error %d", status)
		}
		return fmt.Errorf("SOCKS5 proxy could not connect: %s", reason)
	}
	var addressLength int
	switch header[3] {
	case 1: // IPv4 address
		addressLength = 4
	case 4: // IPv6 address
		addressLength = 16
	case 3: // domain name, prefixed with its length
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		addressLength = int(length[0])
	default:
		return fmt.Errorf("SOCKS5 proxy replied with unknown address type %d", header[3])
	}
	_, err = io.ReadFull(conn, make([]byte, addressLength+2)) // address and port
	return err
}
