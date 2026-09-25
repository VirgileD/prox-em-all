package netfilter

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Installing rules needs root; test/integration/run.sh covers it. These tests
// document the exact rules.
func TestRedirectRules(t *testing.T) {
	r := Redirect{
		ListenPort: 3129,
		ProxyPorts: []uint16{80, 443},
		Mark:       5,
		NoRedirect: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8")},
		Routed:     true,
	}
	redirect := []string{
		"-p udp --dport 53 -j REDIRECT --to-ports 3129",
		"-d 10.0.0.0/8 -j RETURN",
		"-d 127.0.0.0/8 -j RETURN",
		"-p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 3129",
	}
	want := map[string][]string{
		"nat OUTPUT":     append([]string{"-m mark --mark 5 -j RETURN"}, redirect...),
		"nat PREROUTING": redirect,
		"filter INPUT": {
			"-p tcp --dport 3129 -m conntrack --ctstate DNAT -j ACCEPT",
			"-p udp --dport 3129 -m conntrack --ctstate DNAT -j ACCEPT",
		},
		"filter OUTPUT": {
			"-p tcp --dport 3129 -m addrtype --dst-type LOCAL -m mark --mark 5 -j REJECT",
			"-p udp --dport 3129 -m addrtype --dst-type LOCAL -m mark --mark 5 -j REJECT",
		},
	}
	for _, hook := range hooks {
		name := hook.table + " " + hook.chain
		if got := joinRules(r.rules(hook.table, hook.chain)); !reflect.DeepEqual(got, want[name]) {
			t.Errorf("%s rules:\n got %q\nwant %q", name, got, want[name])
		}
	}
}

func TestRoutedTrafficIsOnlyRedirectedWhenRequested(t *testing.T) {
	r := Redirect{ListenPort: 3129, ProxyPorts: []uint16{443}, Mark: 5}
	if got := r.rules("nat", "PREROUTING"); got != nil {
		t.Errorf("nat PREROUTING rules = %q, want none", joinRules(got))
	}
}

func joinRules(rules [][]string) []string {
	var joined []string
	for _, rule := range rules {
		joined = append(joined, strings.Join(rule, " "))
	}
	return joined
}

func TestLocalNetworksIncludesLoopback(t *testing.T) {
	networks, err := LocalNetworks()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(networks, netip.MustParsePrefix("127.0.0.0/8")) {
		t.Errorf("got %v, want it to contain 127.0.0.0/8", networks)
	}
}
