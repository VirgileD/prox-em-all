package netfilter

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// OriginalDNSServer returns the DNS server a query redirected by the iptables
// rules was sent to. UDP sockets cannot tell, so the answer comes from the
// kernel's connection tracking table: the entry of a DNS query from client
// whose answers come from listenPort. Reading the table requires CAP_NET_ADMIN.
func OriginalDNSServer(client netip.AddrPort, listenPort uint16) (netip.AddrPort, error) {
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("read connection tracking table: %w", err)
	}
	for _, flow := range flows {
		query, answer := flow.Forward, flow.Reverse
		srcIP, _ := netip.AddrFromSlice(query.SrcIP)
		if query.Protocol == unix.IPPROTO_UDP &&
			srcIP.Unmap() == client.Addr().Unmap() && query.SrcPort == client.Port() &&
			query.DstPort == dnsPort && answer.SrcPort == listenPort {
			dstIP, _ := netip.AddrFromSlice(query.DstIP)
			return netip.AddrPortFrom(dstIP.Unmap(), query.DstPort), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("no redirected DNS query from %s in the connection tracking table", client)
}

// forgetClientDNSQueries deletes the connection tracking entries of the DNS
// queries of the proxy's clients. A UDP flow is redirected, or not, on its
// first packet only, and its entry lasts up to two minutes: after the rules
// change, a client query reusing the source port of an older one would follow
// the old rules, to a listen port no longer in use or around the proxy.
// Without an entry, it follows the current rules. The proxy's own queries,
// in their own zone, are kept: their answers may be on their way.
func forgetClientDNSQueries() error {
	if _, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, clientDNSQueries{}); err != nil {
		return fmt.Errorf("delete DNS queries from the connection tracking table: %w", err)
	}
	return nil
}

// clientDNSQueries matches the entries of DNS queries outside the proxy's
// conntrack zone. Deleting the entry of a query that is not the proxy's
// business is harmless: its next packet creates a new one.
type clientDNSQueries struct{}

func (clientDNSQueries) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return flow.Forward.Protocol == unix.IPPROTO_UDP && flow.Forward.DstPort == dnsPort && flow.Zone != ownConntrackZone
}
