// Package hostcache remembers the hostname each IP address was resolved from,
// so that connections to an address can be matched against hostname rules.
package hostcache

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Cache maps IP addresses to hostnames. It is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	entries map[netip.Addr]entry
	maxSize int
}

type entry struct {
	hostname string
	expires  time.Time
}

// New returns a cache holding at most maxSize addresses.
func New(maxSize int) *Cache {
	return &Cache{entries: make(map[netip.Addr]entry), maxSize: maxSize}
}

// Add remembers for ttl that addr was resolved from hostname.
// A trailing dot, as in DNS messages ("example.com."), is removed.
func (c *Cache) Add(addr netip.Addr, hostname string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.entries[addr]; !known && len(c.entries) >= c.maxSize {
		c.makeRoom()
	}
	c.entries[addr] = entry{
		hostname: strings.TrimSuffix(hostname, "."),
		expires:  time.Now().Add(ttl),
	}
}

// Lookup returns the hostname addr was resolved from, or "" if it is unknown or expired.
func (c *Cache) Lookup(addr netip.Addr) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[addr]
	if !ok || time.Now().After(e.expires) {
		return ""
	}
	return e.hostname
}

// makeRoom removes the expired entries then, while the cache is more than 90%
// full, arbitrary ones: the cache can then take many additions before it has
// to be scanned again.
func (c *Cache) makeRoom() {
	now := time.Now()
	for addr, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, addr)
		}
	}
	for addr := range c.entries {
		if len(c.entries) <= c.maxSize*9/10 {
			break
		}
		delete(c.entries, addr)
	}
}
