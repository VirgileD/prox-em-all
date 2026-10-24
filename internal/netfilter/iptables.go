// Package netfilter is the Linux-specific plumbing of the proxy: the iptables
// rules redirecting traffic to it, the firewall mark on its own sockets, and
// the lookup of where redirected traffic was originally sent.
package netfilter

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// dnsPort is the destination port of the DNS queries redirected to the proxy.
const dnsPort = 53

// Redirect describes the traffic redirected to the proxy.
type Redirect struct {
	ListenPort uint16         // port the proxy listens on, for TCP and DNS
	ProxyPorts []uint16       // TCP destination ports redirected to the proxy
	Mark       int            // mark of the proxy's own packets, which are never redirected
	NoRedirect []netip.Prefix // TCP destinations never redirected

	// Routed also redirects the traffic routed through this host. The proxy
	// must then listen on all addresses: routed traffic is redirected to the
	// address of the interface it arrives on, local traffic to 127.0.0.1.
	Routed bool

	// WSLMirrored adds the routing rules keeping the traffic redirected to
	// 127.0.0.1 on this host in WSL2's mirrored networking mode (see loopback.go).
	WSLMirrored bool
}

// hooks are the built-in chains the proxy may add rules to. Each of them gets
// a single rule jumping to a chain owned by the proxy, named chainPrefix + chain
// (e.g. PROX_EM_ALL_OUTPUT in the nat table). All rules can therefore be
// removed without knowing the configuration they were installed with.
var hooks = []struct{ table, chain string }{
	{"nat", "OUTPUT"},     // traffic of local processes
	{"nat", "PREROUTING"}, // traffic routed through this host
	{"filter", "INPUT"},
	{"filter", "OUTPUT"},
}

const chainPrefix = "PROX_EM_ALL_"

// Install adds the redirection rules, and the loopback routing rules if
// requested, replacing any left over by a previous run. On failure, the rules
// installed so far are removed.
func Install(r Redirect) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	if err := remove(ipt); err != nil {
		return err
	}
	if r.WSLMirrored {
		if err := addLoopbackRules(r.ListenPort); err != nil {
			return errors.Join(err, remove(ipt))
		}
	}
	for _, hook := range hooks {
		if err := r.install(ipt, hook.table, hook.chain); err != nil {
			return errors.Join(err, remove(ipt))
		}
	}
	return nil
}

// install creates the proxy's own chain for a built-in chain, and makes the
// built-in chain jump to it before any other rule.
func (r Redirect) install(ipt *iptables.IPTables, table, chain string) error {
	rules := r.rules(table, chain)
	if len(rules) == 0 {
		return nil
	}
	ownChain := chainPrefix + chain
	if err := ipt.NewChain(table, ownChain); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := ipt.Append(table, ownChain, rule...); err != nil {
			return err
		}
	}
	return ipt.Insert(table, chain, 1, "-j", ownChain)
}

// Remove deletes the rules added by Install, loopback routing rules included. There is nothing to do if none are installed.
func Remove() error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return remove(ipt)
}

func remove(ipt *iptables.IPTables) error {
	errs := []error{removeLoopbackRules()}
	for _, hook := range hooks {
		ownChain := chainPrefix + hook.chain
		exists, err := ipt.ChainExists(hook.table, ownChain)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if exists {
			errs = append(errs,
				ipt.DeleteIfExists(hook.table, hook.chain, "-j", ownChain),
				ipt.ClearChain(hook.table, ownChain),
				ipt.DeleteChain(hook.table, ownChain),
			)
		}
	}
	return errors.Join(errs...)
}

// rules returns the rules of the proxy's own chain for a built-in chain,
// or nothing if the proxy does not need that chain.
func (r Redirect) rules(table, chain string) [][]string {
	mark := strconv.Itoa(r.Mark)
	listenPort := strconv.Itoa(int(r.ListenPort))

	switch table + " " + chain {
	case "nat OUTPUT":
		// The proxy's own traffic goes where it was sent.
		ownTraffic := []string{"-m", "mark", "--mark", mark, "-j", "RETURN"}
		return append([][]string{ownTraffic}, r.redirectRules()...)

	case "nat PREROUTING":
		if !r.Routed {
			return nil
		}
		return r.redirectRules()

	case "filter INPUT":
		// Accept redirected traffic even if the firewall would otherwise drop
		// it, and drop traffic sent straight to the listen port: listening on
		// 0.0.0.0 must not expose the proxy to the network.
		return [][]string{
			{"-p", "tcp", "--dport", listenPort, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
			{"-p", "udp", "--dport", listenPort, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
			{"-p", "tcp", "--dport", listenPort, "-j", "DROP"},
			{"-p", "udp", "--dport", listenPort, "-j", "DROP"},
		}

	case "filter OUTPUT":
		// The proxy must not connect to itself, for example to forward a
		// connection or a datagram sent straight to its listen port: it would
		// then forward its own connection again and again.
		return [][]string{
			{"-p", "tcp", "--dport", listenPort, "-m", "addrtype", "--dst-type", "LOCAL", "-m", "mark", "--mark", mark, "-j", "REJECT"},
			{"-p", "udp", "--dport", listenPort, "-m", "addrtype", "--dst-type", "LOCAL", "-m", "mark", "--mark", mark, "-j", "REJECT"},
		}
	}
	return nil
}

// redirectRules redirect DNS queries to the proxy, whatever the DNS server,
// then TCP connections to the proxy ports, except to the NoRedirect networks.
func (r Redirect) redirectRules() [][]string {
	listenPort := strconv.Itoa(int(r.ListenPort))
	rules := [][]string{{"-p", "udp", "--dport", strconv.Itoa(dnsPort), "-j", "REDIRECT", "--to-ports", listenPort}}
	for _, network := range r.NoRedirect {
		rules = append(rules, []string{"-d", network.String(), "-j", "RETURN"})
	}
	return append(rules, []string{"-p", "tcp", "-m", "multiport", "--dports", joinPorts(r.ProxyPorts), "-j", "REDIRECT", "--to-ports", listenPort})
}

func joinPorts(ports []uint16) string {
	var s []string
	for _, port := range ports {
		s = append(s, strconv.Itoa(int(port)))
	}
	return strings.Join(s, ",")
}
