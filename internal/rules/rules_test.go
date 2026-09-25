package rules

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/VirgileD/prox-em-all/internal/config"
)

func TestMatch(t *testing.T) {
	rules, err := Compile([]config.Rule{
		{Name: "lan", Destinations: []string{"10.0.0.1", "192.168.0.0/16"}},
		{Name: "corp", Destinations: []string{`.*\.corp\.example\.com`}, Proxies: []string{"proxy.example.com:3128"}},
		{Name: "catch-all", Destinations: []string{"0.0.0.0/0"}, Proxies: []string{"socks5://10.9.9.9:1080"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		addr     string
		hostname string
		want     string // rule name, or "" for no match
	}{
		{"10.0.0.1", "", "lan"},
		{"192.168.4.2", "", "lan"},
		{"192.168.4.2", "git.corp.example.com", "lan"}, // first matching rule wins
		{"172.16.0.1", "git.corp.example.com", "corp"},
		{"172.16.0.1", "GIT.Corp.Example.com", "corp"},                   // hostnames are case-insensitive
		{"172.16.0.1", "git.corp.example.com.attacker.net", "catch-all"}, // patterns match the whole hostname
		{"172.16.0.1", "", "catch-all"},                                  // unknown hostname: only IP rules can match
		{"2001:db8::1", "", ""},                                          // IPv4 networks do not match IPv6 addresses
	}
	for _, tt := range tests {
		got := Match(rules, netip.MustParseAddr(tt.addr), tt.hostname)
		var gotName string
		if got != nil {
			gotName = got.Name
		}
		if gotName != tt.want {
			t.Errorf("Match(%s, %q) = %q, want %q", tt.addr, tt.hostname, gotName, tt.want)
		}
	}
}

func TestMatchWithoutRules(t *testing.T) {
	if got := Match(nil, netip.MustParseAddr("10.0.0.1"), "example.com"); got != nil {
		t.Errorf("got rule %q, want no match", got.Name)
	}
}

func TestCompileParsesProxies(t *testing.T) {
	rules, err := Compile([]config.Rule{{Name: "r", Proxies: []string{
		"proxy.example.com:3128",
		"http://user:secret@10.0.0.1:8080",
		"socks5://10.0.0.2:1080",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, proxy := range rules[0].Proxies {
		got = append(got, proxy.String())
	}
	want := "http://proxy.example.com:3128 http://user:secret@10.0.0.1:8080 socks5://10.0.0.2:1080"
	if strings.Join(got, " ") != want {
		t.Errorf("got proxies %q, want %q", strings.Join(got, " "), want)
	}
}

func TestCompileRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name    string
		rule    config.Rule
		wantErr string
	}{
		{"glob instead of regexp", config.Rule{Name: "r", Destinations: []string{"*.example.com"}}, "not an IP address, a CIDR network or a valid regular expression"},
		{"unsupported proxy scheme", config.Rule{Name: "r", Proxies: []string{"https://proxy:443"}}, "scheme must be http or socks5"},
		{"proxy without port", config.Rule{Name: "r", Proxies: []string{"http://proxy"}}, "host and port are required"},
		{"password is not logged", config.Rule{Name: "r", Proxies: []string{"ftp://user:secret@proxy:21"}}, "user:xxxxx@proxy"},
		{"password is not logged on parse errors", config.Rule{Name: "r", Proxies: []string{"http://user:secret@proxy:31x8"}}, "invalid port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile([]config.Rule{tt.rule})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || strings.Contains(err.Error(), "secret") {
				t.Errorf("got error %v, want it to contain %q (and no password)", err, tt.wantErr)
			}
		})
	}
}
