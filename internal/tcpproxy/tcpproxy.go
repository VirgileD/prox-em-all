// Package tcpproxy forwards the TCP connections redirected to the proxy to
// their original destination, directly or through upstream proxies.
package tcpproxy

import (
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/VirgileD/prox-em-all/internal/credentials"
	"github.com/VirgileD/prox-em-all/internal/hostcache"
	"github.com/VirgileD/prox-em-all/internal/rules"
)

// stats counts connections by outcome. expvar publishes them under /debug/vars.
var stats = expvar.NewMap("connections")

// Server forwards redirected TCP connections.
type Server struct {
	Rules     []*rules.Rule
	Hostnames *hostcache.Cache

	// Dialer opens the connections to destinations and upstream proxies.
	Dialer *net.Dialer

	// OriginalDestination returns where a redirected connection was sent.
	OriginalDestination func(*net.TCPConn) (netip.AddrPort, error)

	// RelayRedirects makes the server relay a 3xx answer from an HTTP proxy
	// to the client, instead of trying the next proxy.
	RelayRedirects bool

	// Injector, when set, replaces the credentials in the requests to the
	// servers it intercepts.
	Injector *credentials.Injector
}

// Serve handles the connections accepted on listener until it is closed.
func (s *Server) Serve(listener *net.TCPListener) error {
	for {
		conn, err := listener.AcceptTCP()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			// For instance when out of file descriptors: pause instead of spinning.
			slog.Warn("cannot accept connection", "error", err)
			stats.Add("accept_errors", 1)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(client *net.TCPConn) {
	defer client.Close()
	log := slog.With("client", client.RemoteAddr())

	destination, err := s.OriginalDestination(client)
	if err != nil {
		log.Warn("cannot find original destination", "error", err)
		stats.Add("failed", 1)
		return
	}
	hostname := s.Hostnames.Lookup(destination.Addr())
	log = log.With("destination", destination, "hostname", hostname)

	rule := rules.Match(s.Rules, destination.Addr(), hostname)
	if rule != nil {
		log = log.With("rule", rule.Name)
	}

	// The ClientHello tells whether the connection is to a server whose
	// credentials are replaced. It is read before connecting, and forwarded after.
	var hello credentials.ClientHello
	if s.Injector != nil && slices.Contains(s.Injector.Ports(), destination.Port()) {
		hello = credentials.ReadClientHello(client)
	}

	upstream, upstreamReader := s.connect(log, client, destination, hostname, rule)
	if upstream == nil {
		return
	}
	defer upstream.Close()

	if s.Injector != nil && s.Injector.Intercepts(hello.ServerName, destination.Port()) {
		s.Injector.Intercept(log.With("server", hello.ServerName), client, hello, upstream, upstreamReader, destination.Port())
		return
	}
	if _, err := upstream.Write(hello.Raw); err != nil {
		log.Warn("cannot forward the start of the connection", "error", err)
		return
	}
	pipe(client, upstream, upstreamReader)
}

// connect opens a connection to destination as rule says: directly, or
// through its proxies. Data from the connection must be read from the
// returned reader. It returns nil when no connection could be opened.
func (s *Server) connect(log *slog.Logger, client *net.TCPConn, destination netip.AddrPort, hostname string, rule *rules.Rule) (*net.TCPConn, io.Reader) {
	if rule == nil || len(rule.Proxies) == 0 {
		return s.connectDirectly(log, destination)
	}
	return s.connectThroughProxies(log, client, destination, hostname, rule.Proxies)
}

func (s *Server) connectDirectly(log *slog.Logger, destination netip.AddrPort) (*net.TCPConn, io.Reader) {
	upstream, err := s.dialTCP(destination.String())
	if err != nil {
		log.Warn("direct connection failed", "error", err)
		stats.Add("failed", 1)
		return nil, nil
	}
	log.Debug("connected directly")
	stats.Add("direct", 1)
	return upstream, upstream
}

// connectThroughProxies tries the proxies in turn until one opens a tunnel to the destination.
func (s *Server) connectThroughProxies(log *slog.Logger, client *net.TCPConn, destination netip.AddrPort, hostname string, proxies []*url.URL) (*net.TCPConn, io.Reader) {
	// Proxies are given the hostname when it is known, so that their own
	// hostname-based policies apply.
	target := destination.String()
	if hostname != "" {
		target = net.JoinHostPort(hostname, strconv.Itoa(int(destination.Port())))
	}
	clientIP := client.RemoteAddr().(*net.TCPAddr).IP.String()

	for _, proxy := range proxies {
		log := log.With("proxy", proxy.Redacted())
		upstream, upstreamReader, err := s.dialProxy(proxy, target, clientIP)

		var redirect *redirectError
		if errors.As(err, &redirect) && s.RelayRedirects {
			log.Info("relaying redirection from proxy", "status", redirect.status)
			stats.Add("redirected", 1)
			_, _ = client.Write(redirect.response)
			return nil, nil
		}
		if err != nil {
			log.Warn("proxy connection failed", "error", err)
			continue
		}
		log.Debug("connected through proxy")
		stats.Add("proxied", 1)
		return upstream, upstreamReader
	}
	log.Warn("all proxies failed, closing connection")
	stats.Add("failed", 1)
	return nil, nil
}

// pipe copies data between client and upstream in both directions until both
// directions are done. Upstream data is read from upstreamReader: upstream
// itself, or a reader that may already hold data received from it.
func pipe(client, upstream *net.TCPConn, upstreamReader io.Reader) {
	copyData := func(dst *net.TCPConn, src io.Reader) {
		if _, err := io.Copy(dst, src); err != nil {
			// A broken connection ends the other direction too.
			client.Close()
			upstream.Close()
			return
		}
		// Tell dst no more data is coming, while still reading its answer.
		_ = dst.CloseWrite()
	}
	var wg sync.WaitGroup
	wg.Go(func() { copyData(upstream, client) })
	wg.Go(func() { copyData(client, upstreamReader) })
	wg.Wait()
}
