// Package rules decides how a destination is reached: directly, or through
// which upstream proxies.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/VirgileD/prox-em-all/internal/config"
)

// Rule is a validated config.Rule, ready for matching.
type Rule struct {
	Name string

	// Proxies are the upstream proxies to try in order. Their scheme is
	// "http" or "socks5". An empty list means a direct connection.
	Proxies []*url.URL

	networks  []netip.Prefix   // from IP address and CIDR destinations
	hostnames []*regexp.Regexp // from all other destinations
}

// Compile validates the configured rules and prepares them for matching.
func Compile(configured []config.Rule) ([]*Rule, error) {
	var compiled []*Rule
	for _, c := range configured {
		rule := &Rule{Name: c.Name}
		for _, destination := range c.Destinations {
			if err := rule.addDestination(destination); err != nil {
				return nil, fmt.Errorf("rule %q: %w", c.Name, err)
			}
		}
		for _, spec := range c.Proxies {
			proxy, err := parseProxy(spec)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", c.Name, err)
			}
			rule.Proxies = append(rule.Proxies, proxy)
		}
		compiled = append(compiled, rule)
	}
	return compiled, nil
}

// Match returns the first rule matching the destination address or hostname,
// or nil if none does. hostname is empty when it is not known, in which case
// only IP address and CIDR destinations can match.
func Match(rules []*Rule, addr netip.Addr, hostname string) *Rule {
	for _, rule := range rules {
		if rule.matches(addr, hostname) {
			return rule
		}
	}
	return nil
}

func (r *Rule) matches(addr netip.Addr, hostname string) bool {
	for _, network := range r.networks {
		if network.Contains(addr) {
			return true
		}
	}
	if hostname == "" {
		return false
	}
	for _, pattern := range r.hostnames {
		if pattern.MatchString(hostname) {
			return true
		}
	}
	return false
}

// addDestination adds an IP address ("10.0.0.1"), a CIDR network ("10.0.0.0/8")
// or a hostname regular expression (".*\.example\.com").
func (r *Rule) addDestination(destination string) error {
	if network, err := netip.ParsePrefix(destination); err == nil {
		r.networks = append(r.networks, network)
		return nil
	}
	if addr, err := netip.ParseAddr(destination); err == nil {
		r.networks = append(r.networks, netip.PrefixFrom(addr, addr.BitLen()))
		return nil
	}
	// Hostnames are case-insensitive, and the pattern must match the whole
	// hostname: "example\.com" must not match "example.com.attacker.net".
	pattern, err := regexp.Compile(`(?i)^(?:` + destination + `)$`)
	if err != nil {
		return fmt.Errorf("destination %q is not an IP address, a CIDR network or a valid regular expression: %w", destination, err)
	}
	r.hostnames = append(r.hostnames, pattern)
	return nil
}

// parseProxy parses "[scheme://][user[:password]@]host:port", where scheme is
// "http" (the default) or "socks5".
func parseProxy(spec string) (*url.URL, error) {
	if !strings.Contains(spec, "://") {
		spec = "http://" + spec
	}
	proxy, err := url.Parse(spec)
	if err != nil {
		// Not err itself: it quotes the whole URL, password included.
		return nil, fmt.Errorf("invalid proxy URL: %w", errors.Unwrap(err))
	}
	if proxy.Scheme != "http" && proxy.Scheme != "socks5" {
		return nil, fmt.Errorf("proxy %q: scheme must be http or socks5", proxy.Redacted())
	}
	if proxy.Hostname() == "" || proxy.Port() == "" {
		return nil, fmt.Errorf("proxy %q: host and port are required", proxy.Redacted())
	}
	return proxy, nil
}
