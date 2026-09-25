package netfilter

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// WSL2's mirrored networking mode shares localhost between Linux and Windows:
// routing rules at priority 1 send TCP and UDP traffic to 127.0.0.1 through
// Windows (interface loopback0). Traffic redirected to the proxy, which
// iptables sends to 127.0.0.1, would take that path and come back as a new
// connection, with another source port: the proxy could then no longer find
// where it was originally sent. The loopback rules, placed before WSL's,
// keep the traffic to the listen port on this host.

// loopbackRulePriority is the priority of the loopback rules. It must be
// lower than WSL's rules, which are at priority 1.
const loopbackRulePriority = 0

// loopbackRules returns the loopback rules for the proxy's listen port.
func loopbackRules(listenPort uint16) []*netlink.Rule {
	return []*netlink.Rule{
		loopbackRule(unix.IPPROTO_TCP, listenPort),
		loopbackRule(unix.IPPROTO_UDP, listenPort),
	}
}

// loopbackRule routes the traffic of a protocol to 127.0.0.1:port with the
// "local" routing table, like `ip rule add pref 0 to 127.0.0.1 ipproto udp dport 3129 lookup local`.
func loopbackRule(protocol int, port uint16) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Priority = loopbackRulePriority
	rule.Dst = &net.IPNet{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)}
	rule.IPProto = protocol
	rule.Dport = netlink.NewRulePortRange(port, port)
	rule.Table = unix.RT_TABLE_LOCAL
	return rule
}

// isLoopbackRule reports whether a routing rule is a loopback rule, whatever
// the listen port it was added for.
func isLoopbackRule(rule netlink.Rule) bool {
	return rule.Priority == loopbackRulePriority && rule.Table == unix.RT_TABLE_LOCAL &&
		rule.Dst != nil && rule.Dst.String() == "127.0.0.1/32" &&
		(rule.IPProto == unix.IPPROTO_TCP || rule.IPProto == unix.IPPROTO_UDP) &&
		rule.Dport != nil && rule.Dport.Start == rule.Dport.End
}

func addLoopbackRules(listenPort uint16) error {
	for _, rule := range loopbackRules(listenPort) {
		if err := netlink.RuleAdd(rule); err != nil {
			return err
		}
	}
	return nil
}

// removeLoopbackRules deletes the loopback rules, whatever their listen port.
// There is nothing to do if none are installed.
func removeLoopbackRules() error {
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	var errs []error
	for _, rule := range rules {
		if isLoopbackRule(rule) {
			errs = append(errs, netlink.RuleDel(loopbackRule(rule.IPProto, rule.Dport.Start)))
		}
	}
	return errors.Join(errs...)
}
