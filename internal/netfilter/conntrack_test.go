package netfilter

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestClientDNSQueries(t *testing.T) {
	tests := []struct {
		name          string
		protocol      uint8
		queryDstPort  uint16
		answerSrcPort uint16
		zone          uint16
		want          bool
	}{
		{"query redirected to the listen port", unix.IPPROTO_UDP, 53, 3129, 0, true},
		{"query not redirected", unix.IPPROTO_UDP, 53, 53, 0, true},
		{"query forwarded by the proxy", unix.IPPROTO_UDP, 53, 53, ownConntrackZone, false},
		{"other UDP traffic", unix.IPPROTO_UDP, 123, 123, 0, false},
		{"TCP connection", unix.IPPROTO_TCP, 53, 3129, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &netlink.ConntrackFlow{
				Zone:    tt.zone,
				Forward: netlink.IPTuple{Protocol: tt.protocol, SrcIP: net.IPv4(10, 0, 0, 2), DstIP: net.IPv4(10, 0, 0, 53), SrcPort: 40000, DstPort: tt.queryDstPort},
				Reverse: netlink.IPTuple{Protocol: tt.protocol, SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), SrcPort: tt.answerSrcPort, DstPort: 40000},
			}
			if got := (clientDNSQueries{}).MatchConntrackFlow(flow); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
