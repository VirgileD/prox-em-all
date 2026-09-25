// Package dnsproxy forwards the DNS queries redirected to the proxy to the
// server they were sent to, and remembers the addresses in the answers so that
// connections to these addresses can be matched against hostname rules.
package dnsproxy

import (
	"bytes"
	"errors"
	"expvar"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/VirgileD/prox-em-all/internal/hostcache"
)

const (
	// exchangeTimeout bounds the time a DNS server takes to answer.
	exchangeTimeout = 5 * time.Second

	// hostnameTTLMargin extends how long addresses are remembered after their
	// DNS record expires, as clients often keep using them a little longer.
	hostnameTTLMargin = 5 * time.Minute

	// maxConcurrentQueries bounds the queries handled at once, so that a flood
	// of queries cannot exhaust memory or file descriptors. Queries beyond it
	// are dropped, and clients send them again.
	maxConcurrentQueries = 100
)

// stats counts queries by outcome. expvar publishes them under /debug/vars.
var stats = expvar.NewMap("dns")

// Server forwards redirected DNS queries.
type Server struct {
	Hostnames *hostcache.Cache

	// Dialer opens the connections to DNS servers.
	Dialer *net.Dialer

	// OriginalDestination returns the DNS server a query from client was sent to.
	OriginalDestination func(client netip.AddrPort) (netip.AddrPort, error)
}

// Serve answers the queries received on conn until it is closed.
func (s *Server) Serve(conn *net.UDPConn) error {
	// Answers must be sent from the address the query was received on, or
	// connection tracking cannot turn them back into answers from the
	// original server. Ask the kernel for that address with each packet.
	packetConn := ipv4.NewPacketConn(conn)
	if err := packetConn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return err
	}
	handling := make(chan struct{}, maxConcurrentQueries)
	buf := make([]byte, 65535)
	for {
		n, received, client, err := packetConn.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			slog.Warn("cannot read DNS query", "error", err)
			stats.Add("read_errors", 1)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case handling <- struct{}{}:
			query := bytes.Clone(buf[:n])
			go func() {
				defer func() { <-handling }()
				s.handle(packetConn, query, client.(*net.UDPAddr), received)
			}()
		default:
			stats.Add("dropped", 1)
		}
	}
}

func (s *Server) handle(conn *ipv4.PacketConn, query []byte, client *net.UDPAddr, received *ipv4.ControlMessage) {
	log := slog.With("client", client)
	server, err := s.OriginalDestination(client.AddrPort())
	if err != nil {
		log.Warn("cannot find original DNS server", "error", err)
		stats.Add("failed", 1)
		return
	}
	answer, err := s.exchange(query, server)
	if err != nil {
		log.Warn("DNS query failed", "server", server, "error", err)
		stats.Add("failed", 1)
		return
	}
	s.rememberAddresses(answer)

	var reply *ipv4.ControlMessage
	if received != nil {
		reply = &ipv4.ControlMessage{Src: received.Dst}
	}
	if _, err := conn.WriteTo(answer, reply, client); err != nil {
		log.Warn("cannot send DNS answer", "error", err)
		stats.Add("failed", 1)
		return
	}
	stats.Add("answered", 1)
}

// exchange sends query to server and returns its answer.
func (s *Server) exchange(query []byte, server netip.AddrPort) ([]byte, error) {
	conn, err := s.Dialer.Dial("udp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(exchangeTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	answer := make([]byte, 65535)
	n, err := conn.Read(answer)
	if err != nil {
		return nil, err
	}
	return answer[:n], nil
}

// rememberAddresses records the IPv4 addresses found in a DNS answer as
// belonging to the queried hostname, even when they were reached through
// CNAME records: the hostname the client asked for is the one rules refer to.
// Malformed answers are ignored; the client will deal with them.
func (s *Server) rememberAddresses(answer []byte) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(answer); err != nil {
		return
	}
	question, err := parser.Question()
	if err != nil || !isHostname(question.Name.String()) {
		return
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return
	}
	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			return // including dnsmessage.ErrSectionDone, after the last answer
		}
		if header.Type != dnsmessage.TypeA || header.Class != dnsmessage.ClassINET {
			if err := parser.SkipAnswer(); err != nil {
				return
			}
			continue
		}
		record, err := parser.AResource()
		if err != nil {
			return
		}
		ttl := time.Duration(header.TTL)*time.Second + hostnameTTLMargin
		s.Hostnames.Add(netip.AddrFrom4(record.A), question.Name.String(), ttl)
	}
}

// isHostname reports whether name only has the characters of a hostname:
// letters, digits, hyphens, underscores and dots. DNS names may contain any
// byte, which must not reach logs or the requests sent to upstream proxies.
func isHostname(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		isValid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		return !isValid
	})
}
