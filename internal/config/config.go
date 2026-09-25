// Package config loads and validates the prox-em-all configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
)

// Config is the content of the JSON configuration file.
type Config struct {
	// ListenEndpoint is the address and port the proxy listens on, for
	// redirected TCP connections and DNS queries alike. With 127.0.0.1, only
	// the traffic of this host is redirected; with 0.0.0.0, the traffic routed
	// through this host is also redirected.
	ListenEndpoint netip.AddrPort `json:"listenEndpoint"`

	// ProxyPorts are the TCP destination ports redirected to the proxy.
	ProxyPorts []uint16 `json:"proxyPorts"`

	// IPTableMark is set on the proxy's own packets so that iptables does not
	// redirect them back to the proxy.
	IPTableMark int `json:"ipTableMark"`

	// NoProxyList holds networks to which TCP connections are never redirected
	// to the proxy. The networks of the host's interfaces are added automatically.
	NoProxyList []netip.Prefix `json:"noProxyList"`

	// RelayingRedirectResponse makes the proxy relay a 3xx answer from an HTTP
	// upstream proxy (such as a login page) to the client, instead of trying the next proxy.
	RelayingRedirectResponse bool `json:"relayingRedirectResponse"`

	// LogLevel is one of "debug", "info", "warn" or "error".
	LogLevel slog.Level `json:"logLevel"`

	// DebugEndpoint, when set, is the address serving pprof profiles and
	// expvar statistics over HTTP, for example "127.0.0.1:6060".
	DebugEndpoint string `json:"debugEndpoint"`

	// WSLMirroredNetworking must be set on WSL2 with networkingMode=mirrored,
	// which otherwise sends the traffic redirected to 127.0.0.1 through Windows.
	WSLMirroredNetworking bool `json:"wslMirroredNetworking"`

	// Rules decide how each destination is reached. The first matching rule wins,
	// and destinations matching no rule are connected to directly.
	Rules []Rule `json:"rules"`
}

// Rule sends the destinations it matches through its proxies.
type Rule struct {
	// Name identifies the rule in logs.
	Name string `json:"name"`

	// Destinations are IP addresses, CIDR networks, or regular expressions
	// that must match the whole destination hostname.
	Destinations []string `json:"destinations"`

	// Proxies are tried in order until one accepts the connection, for example
	// "http://user:password@proxy.example.com:3128" or "socks5://10.0.0.1:1080".
	// An empty list means a direct connection.
	Proxies []string `json:"proxies"`
}

// Default returns the configuration used for settings missing from the file.
func Default() Config {
	return Config{
		ListenEndpoint:           netip.MustParseAddrPort("127.0.0.1:3129"),
		ProxyPorts:               []uint16{80, 443},
		IPTableMark:              5,
		RelayingRedirectResponse: true,
		LogLevel:                 slog.LevelInfo,
	}
}

// Load reads and validates the configuration file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a JSON configuration. Unknown settings are
// rejected, so that a typo does not silently fall back to a default.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	// iptables redirects local traffic to 127.0.0.1, and routed traffic to the
	// address of the interface it arrives on: no other address would receive it.
	listenAddr := c.ListenEndpoint.Addr()
	if (listenAddr != netip.MustParseAddr("127.0.0.1") && listenAddr != netip.IPv4Unspecified()) || c.ListenEndpoint.Port() == 0 {
		return errors.New(`listenEndpoint must be "127.0.0.1:<port>" or "0.0.0.0:<port>"`)
	}
	// iptables' multiport match accepts at most 15 ports.
	if len(c.ProxyPorts) == 0 || len(c.ProxyPorts) > 15 {
		return errors.New("proxyPorts must list between 1 and 15 ports")
	}
	if slices.Contains(c.ProxyPorts, 0) {
		return errors.New("proxyPorts cannot contain port 0")
	}
	if c.IPTableMark <= 0 {
		return errors.New("ipTableMark must be a positive number")
	}
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rules[%d]: name is required", i)
		}
	}
	return nil
}
