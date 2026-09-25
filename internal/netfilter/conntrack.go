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
