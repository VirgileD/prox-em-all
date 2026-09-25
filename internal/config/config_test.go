package config

import (
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("got %+v, want defaults %+v", cfg, Default())
	}
}

func TestParseAllSettings(t *testing.T) {
	cfg, err := Parse([]byte(`{
		"listenEndpoint": "0.0.0.0:4000",
		"proxyPorts": [80, 8080],
		"ipTableMark": 42,
		"noProxyList": ["192.168.0.0/16"],
		"relayingRedirectResponse": false,
		"logLevel": "debug",
		"debugEndpoint": "127.0.0.1:6060",
		"wslMirroredNetworking": true,
		"rules": [{"name": "corp", "destinations": [".*\\.corp"], "proxies": ["http://proxy:3128"]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ListenEndpoint:           netip.MustParseAddrPort("0.0.0.0:4000"),
		ProxyPorts:               []uint16{80, 8080},
		IPTableMark:              42,
		NoProxyList:              []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		RelayingRedirectResponse: false,
		LogLevel:                 slog.LevelDebug,
		DebugEndpoint:            "127.0.0.1:6060",
		WSLMirroredNetworking:    true,
		Rules: []Rule{
			{Name: "corp", Destinations: []string{`.*\.corp`}, Proxies: []string{"http://proxy:3128"}},
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("got  %+v\nwant %+v", cfg, want)
	}
}

func TestParseRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"not json", `{`, "unexpected EOF"},
		{"unknown setting", `{"listenAddress": "127.0.0.1:3129"}`, `unknown field "listenAddress"`},
		{"listen without port", `{"listenEndpoint": "127.0.0.1"}`, "not an ip:port"},
		{"listen on IPv6", `{"listenEndpoint": "[::1]:3129"}`, "listenEndpoint must be"},
		{"listen on a specific address", `{"listenEndpoint": "192.168.1.10:3129"}`, "listenEndpoint must be"},
		{"listen on port 0", `{"listenEndpoint": "127.0.0.1:0"}`, "listenEndpoint must be"},
		{"no proxy ports", `{"proxyPorts": []}`, "between 1 and 15 ports"},
		{"port out of range", `{"proxyPorts": [70000]}`, "proxyPorts"},
		{"port zero", `{"proxyPorts": [0]}`, "port 0"},
		{"mark zero", `{"ipTableMark": 0}`, "ipTableMark"},
		{"network without prefix length", `{"noProxyList": ["10.0.0.1"]}`, `ParsePrefix("10.0.0.1")`},
		{"unknown log level", `{"logLevel": "verbose"}`, "verbose"},
		{"rule without name", `{"rules": [{"destinations": ["10.0.0.1"]}]}`, "rules[0]: name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got error %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
