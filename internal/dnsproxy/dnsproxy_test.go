package dnsproxy

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/VirgileD/prox-em-all/internal/hostcache"
)

func TestQueriesAreForwardedAndAddressesRemembered(t *testing.T) {
	hostnames := hostcache.New(10)
	proxy := startServer(t, &Server{Hostnames: hostnames}, startDNSServer(t))

	tests := []struct {
		hostname string
		want     string
	}{
		{"www.example.com", "192.0.2.10"},
		{"alias.example.com", "192.0.2.10"}, // a CNAME of www.example.com
	}
	for _, tt := range tests {
		addrs, err := lookup(proxy, tt.hostname)
		if err != nil {
			t.Fatalf("lookup %s: %v", tt.hostname, err)
		}
		if !slices.Equal(addrs, []string{tt.want}) {
			t.Errorf("lookup %s = %v, want [%s]", tt.hostname, addrs, tt.want)
		}
		// The address belongs to the hostname the client asked for.
		if got := hostnames.Lookup(netip.MustParseAddr(tt.want)); got != tt.hostname {
			t.Errorf("hostname of %s = %q, want %q", tt.want, got, tt.hostname)
		}
	}
}

func TestUnknownHostname(t *testing.T) {
	hostnames := hostcache.New(10)
	proxy := startServer(t, &Server{Hostnames: hostnames}, startDNSServer(t))

	if addrs, err := lookup(proxy, "unknown.example.com"); err == nil {
		t.Errorf("lookup unknown.example.com = %v, want an error", addrs)
	}
}

func TestInvalidHostnamesAreIgnored(t *testing.T) {
	// DNS names may hold any byte. A malicious DNS server could otherwise
	// inject headers into the CONNECT requests sent to upstream proxies.
	for _, name := range []string{"evil\r\nX-Injected: yes\r\nwww.example.com.", "space in.example.com."} {
		answer := dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 66}},
			}},
		}
		packed, err := answer.Pack()
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{Hostnames: hostcache.New(10)}
		s.rememberAddresses(packed)
		if got := s.Hostnames.Lookup(netip.MustParseAddr("192.0.2.66")); got != "" {
			t.Errorf("hostname %q was remembered", got)
		}
	}
}

// startServer runs s on a local port and returns its address. All queries
// appear to have been sent to dnsServer.
func startServer(t *testing.T, s *Server, dnsServer netip.AddrPort) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s.Dialer = &net.Dialer{}
	s.OriginalDestination = func(netip.AddrPort) (netip.AddrPort, error) { return dnsServer, nil }
	go s.Serve(conn)
	return conn.LocalAddr().String()
}

// lookup resolves hostname with the DNS server at addr.
func lookup(addr, hostname string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return resolver.LookupHost(ctx, hostname+".")
}

// startDNSServer runs a DNS server knowing www.example.com (192.0.2.10) and
// its alias alias.example.com, and returns its address.
func startDNSServer(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	www := dnsmessage.MustNewName("www.example.com.")
	alias := dnsmessage.MustNewName("alias.example.com.")
	aRecord := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: www, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
	}
	cnameRecord := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.CNAMEResource{CNAME: www},
	}

	go func() {
		buf := make([]byte, 1500)
		for {
			n, client, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buf[:n]); err != nil || len(query.Questions) != 1 {
				continue
			}
			question := query.Questions[0]
			answer := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true},
				Questions: query.Questions,
			}
			switch {
			case question.Name != www && question.Name != alias:
				answer.RCode = dnsmessage.RCodeNameError
			case question.Type != dnsmessage.TypeA:
				// No record of this type: an empty answer.
			case question.Name == www:
				answer.Answers = []dnsmessage.Resource{aRecord}
			case question.Name == alias:
				answer.Answers = []dnsmessage.Resource{cnameRecord, aRecord}
			}
			packed, err := answer.Pack()
			if err != nil {
				t.Errorf("pack answer: %v", err)
				continue
			}
			conn.WriteToUDPAddrPort(packed, client)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}
