package tcpproxy

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/VirgileD/prox-em-all/internal/config"
	"github.com/VirgileD/prox-em-all/internal/hostcache"
	"github.com/VirgileD/prox-em-all/internal/rules"
)

// A connection redirected from 192.0.2.1:443, known as www.example.com.
var destination = netip.MustParseAddrPort("192.0.2.1:443")

func TestDirectConnection(t *testing.T) {
	echo := startEchoServer(t)
	proxy := startServer(t, &Server{}, echo)

	if got := exchange(t, proxy, "ping"); got != "echo: ping" {
		t.Errorf("got %q, want %q", got, "echo: ping")
	}
}

func TestHTTPProxy(t *testing.T) {
	upstream := startHTTPProxy(t, func(req *http.Request, client *bufio.ReadWriter) {
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
		switch {
		case req.Method != http.MethodConnect || req.Host != "www.example.com:443":
			t.Errorf("proxy got %s %s, want CONNECT www.example.com:443", req.Method, req.Host)
		case req.Header.Get("Proxy-Authorization") != wantAuth:
			t.Errorf("proxy got Proxy-Authorization %q, want %q", req.Header.Get("Proxy-Authorization"), wantAuth)
		case req.Header.Get("X-Forwarded-For") != "127.0.0.1":
			t.Errorf("proxy got X-Forwarded-For %q, want 127.0.0.1", req.Header.Get("X-Forwarded-For"))
		}
		// Send data right behind the answer, as a server speaking first would:
		// it must not be lost in the proxy's read buffer.
		client.WriteString("HTTP/1.1 200 Connection established\r\n\r\nhello, ")
		echoData(client)
	})
	s := &Server{Rules: compileRules(t, "http://user:secret@"+upstream)}
	s.Hostnames = hostcache.New(10)
	s.Hostnames.Add(destination.Addr(), "www.example.com", time.Minute)
	proxy := startServer(t, s, destination.String())

	if got := exchange(t, proxy, "ping"); got != "hello, echo: ping" {
		t.Errorf("got %q, want %q", got, "hello, echo: ping")
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	upstream := startSOCKS5Proxy(t, "user", "secret", func(target string, client *bufio.ReadWriter) {
		if target != "www.example.com:443" {
			t.Errorf("proxy got target %s, want www.example.com:443", target)
		}
		echoData(client)
	})
	s := &Server{Rules: compileRules(t, "socks5://user:secret@"+upstream)}
	s.Hostnames = hostcache.New(10)
	s.Hostnames.Add(destination.Addr(), "www.example.com", time.Minute)
	proxy := startServer(t, s, destination.String())

	if got := exchange(t, proxy, "ping"); got != "echo: ping" {
		t.Errorf("got %q, want %q", got, "echo: ping")
	}
}

func TestSOCKS5ProxyRejectingCredentials(t *testing.T) {
	upstream := startSOCKS5Proxy(t, "user", "secret", func(string, *bufio.ReadWriter) {
		t.Error("tunnel opened with wrong credentials")
	})
	proxy := startServer(t, &Server{Rules: compileRules(t, "socks5://user:wrong@"+upstream)}, destination.String())

	if got := exchange(t, proxy, ""); got != "" {
		t.Errorf("got %q, want the connection closed", got)
	}
}

func TestNextProxyIsTriedWhenOneFails(t *testing.T) {
	refusing := startHTTPProxy(t, func(req *http.Request, client *bufio.ReadWriter) {
		client.WriteString("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	})
	accepting := startHTTPProxy(t, func(req *http.Request, client *bufio.ReadWriter) {
		if req.Host != destination.String() {
			t.Errorf("proxy got CONNECT %s, want the IP address %s as the hostname is unknown", req.Host, destination)
		}
		client.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		echoData(client)
	})
	s := &Server{Rules: compileRules(t, "127.0.0.1:1", refusing, accepting)} // nothing listens on port 1
	proxy := startServer(t, s, destination.String())

	if got := exchange(t, proxy, "ping"); got != "echo: ping" {
		t.Errorf("got %q, want %q", got, "echo: ping")
	}
}

func TestRedirection(t *testing.T) {
	redirecting := startHTTPProxy(t, func(req *http.Request, client *bufio.ReadWriter) {
		client.WriteString("HTTP/1.1 302 Found\r\nLocation: http://login.example.com/\r\nContent-Length: 5\r\n\r\nlogin")
	})

	t.Run("relayed", func(t *testing.T) {
		proxy := startServer(t, &Server{Rules: compileRules(t, redirecting), RelayRedirects: true}, destination.String())
		got := exchange(t, proxy, "")
		if !strings.HasPrefix(got, "HTTP/1.1 302 Found\r\n") || !strings.Contains(got, "Location: http://login.example.com/") || !strings.HasSuffix(got, "login") {
			t.Errorf("got %q, want the proxy's redirection", got)
		}
	})
	t.Run("not relayed", func(t *testing.T) {
		proxy := startServer(t, &Server{Rules: compileRules(t, redirecting)}, destination.String())
		if got := exchange(t, proxy, ""); got != "" {
			t.Errorf("got %q, want the connection closed", got)
		}
	})
}

// startServer runs s on a local port and returns its address. All its
// connections appear to have been redirected from originalDestination.
func startServer(t *testing.T, s *Server, originalDestination string) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	s.Dialer = &net.Dialer{Timeout: time.Second}
	s.OriginalDestination = func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort(originalDestination), nil
	}
	if s.Hostnames == nil {
		s.Hostnames = hostcache.New(10)
	}
	go s.Serve(listener)
	return listener.Addr().String()
}

func compileRules(t *testing.T, proxies ...string) []*rules.Rule {
	t.Helper()
	compiled, err := rules.Compile([]config.Rule{{Name: "test", Destinations: []string{"0.0.0.0/0"}, Proxies: proxies}})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// startHTTPProxy runs a fake HTTP proxy calling answer for each request, and returns its address.
func startHTTPProxy(t *testing.T, answer func(req *http.Request, client *bufio.ReadWriter)) string {
	return startTCPServer(t, func(conn net.Conn) {
		client := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		req, err := http.ReadRequest(client.Reader)
		if err != nil {
			t.Errorf("proxy cannot read request: %v", err)
			return
		}
		answer(req, client)
		client.Flush()
	})
}

// startSOCKS5Proxy runs a fake SOCKS5 proxy requiring a username and a
// password, calling answer once a tunnel is open, and returns its address.
func startSOCKS5Proxy(t *testing.T, username, password string, answer func(target string, client *bufio.ReadWriter)) string {
	return startTCPServer(t, func(conn net.Conn) {
		client := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		read := func(n int) []byte {
			buf := make([]byte, n)
			io.ReadFull(client, buf)
			return buf
		}
		reply := func(b ...byte) {
			client.Write(b)
			client.Flush()
		}
		read(int(read(2)[1])) // version and authentication methods
		reply(5, 2)           // username and password authentication
		read(1)               // authentication version
		gotUsername := string(read(int(read(1)[0])))
		gotPassword := string(read(int(read(1)[0])))
		if gotUsername != username || gotPassword != password {
			reply(1, 1) // failure
			return
		}
		reply(1, 0)                              // success
		if request := read(4); request[3] != 3 { // version, command, reserved, address type
			t.Errorf("proxy got address type %d, want 3 (domain name)", request[3])
			return
		}
		host := string(read(int(read(1)[0])))
		port := binary.BigEndian.Uint16(read(2))
		reply(5, 0, 0, 1, 0, 0, 0, 0, 0, 0) // success, bound to 0.0.0.0:0
		answer(net.JoinHostPort(host, strconv.Itoa(int(port))), client)
		client.Flush()
	})
}

// startEchoServer runs a server answering "echo: " followed by all the data it received.
func startEchoServer(t *testing.T) string {
	return startTCPServer(t, func(conn net.Conn) {
		client := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		echoData(client)
		client.Flush()
	})
}

// echoData reads until the client stops sending, then answers "echo: " and the data.
func echoData(client *bufio.ReadWriter) {
	client.Flush()
	data, _ := io.ReadAll(client)
	client.WriteString("echo: " + string(data))
}

func startTCPServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// exchange sends message to addr, signals it has nothing more to send, and
// returns everything received until the connection is closed.
func exchange(t *testing.T, addr, message string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return string(answer)
}
