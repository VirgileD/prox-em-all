package netfilter

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Adding routing rules needs root; test/integration/run.sh covers it.
func TestLoopbackRules(t *testing.T) {
	rules := loopbackRules(3129)
	if len(rules) != 2 || rules[0].IPProto != unix.IPPROTO_TCP || rules[1].IPProto != unix.IPPROTO_UDP {
		t.Fatalf("got %v, want a TCP rule and a UDP rule", rules)
	}
	for _, rule := range rules {
		if rule.Priority != 0 || rule.Table != unix.RT_TABLE_LOCAL || rule.Dst.String() != "127.0.0.1/32" ||
			*rule.Dport != (netlink.RulePortRange{Start: 3129, End: 3129}) {
			t.Errorf("got %v, want pref 0 to 127.0.0.1 dport 3129 lookup local", rule)
		}
		if !isLoopbackRule(*rule) {
			t.Errorf("isLoopbackRule(%v) = false, want true", rule)
		}
	}
}

func TestIsLoopbackRuleIgnoresOtherRules(t *testing.T) {
	localhost := &net.IPNet{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}
	tests := []struct {
		name string
		rule netlink.Rule
	}{
		{"kernel default", netlink.Rule{Priority: 0, Table: unix.RT_TABLE_LOCAL}},
		{"WSL mirrored mode", netlink.Rule{Priority: 1, Table: 127, IPProto: unix.IPPROTO_UDP}},
		{"no port", netlink.Rule{Priority: 0, Table: unix.RT_TABLE_LOCAL, Dst: localhost, IPProto: unix.IPPROTO_UDP}},
		{"other table", netlink.Rule{Priority: 0, Table: 127, Dst: localhost, IPProto: unix.IPPROTO_UDP, Dport: netlink.NewRulePortRange(3129, 3129)}},
	}
	for _, tt := range tests {
		if isLoopbackRule(tt.rule) {
			t.Errorf("%s: isLoopbackRule(%v) = true, want false", tt.name, tt.rule)
		}
	}
}
