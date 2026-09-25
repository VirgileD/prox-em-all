package hostcache

import (
	"net/netip"
	"testing"
	"time"
)

var (
	addr1 = netip.MustParseAddr("10.0.0.1")
	addr2 = netip.MustParseAddr("10.0.0.2")
	addr3 = netip.MustParseAddr("10.0.0.3")
)

func TestAddAndLookup(t *testing.T) {
	cache := New(10)
	cache.Add(addr1, "www.example.com.", time.Minute)

	if got := cache.Lookup(addr1); got != "www.example.com" {
		t.Errorf("Lookup(%s) = %q, want %q", addr1, got, "www.example.com")
	}
	if got := cache.Lookup(addr2); got != "" {
		t.Errorf("Lookup(%s) = %q, want no hostname", addr2, got)
	}
}

func TestLatestHostnameWins(t *testing.T) {
	cache := New(10)
	cache.Add(addr1, "a.example.com", time.Minute)
	cache.Add(addr1, "b.example.com", time.Minute)

	if got := cache.Lookup(addr1); got != "b.example.com" {
		t.Errorf("Lookup(%s) = %q, want %q", addr1, got, "b.example.com")
	}
}

func TestExpiredEntriesAreIgnored(t *testing.T) {
	cache := New(10)
	cache.Add(addr1, "old.example.com", -time.Second)

	if got := cache.Lookup(addr1); got != "" {
		t.Errorf("Lookup(%s) = %q, want no hostname", addr1, got)
	}
}

func TestSizeIsBounded(t *testing.T) {
	cache := New(2)
	cache.Add(addr1, "expired.example.com", -time.Second)
	cache.Add(addr2, "two.example.com", time.Minute)
	cache.Add(addr3, "three.example.com", time.Minute) // evicts the expired entry

	if cache.Lookup(addr2) == "" || cache.Lookup(addr3) == "" {
		t.Error("live entries were evicted while an expired one could be")
	}

	cache.Add(netip.MustParseAddr("10.0.0.4"), "four.example.com", time.Minute) // evicts a live entry
	if len(cache.entries) != 2 {
		t.Errorf("cache holds %d entries, want at most 2", len(cache.entries))
	}
}

func TestEvictionLeavesRoom(t *testing.T) {
	cache := New(100)
	for i := range 101 {
		cache.Add(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), "live.example.com", time.Minute)
	}
	// The 101st addition evicted live entries down to 90, then added one.
	if len(cache.entries) != 91 {
		t.Errorf("cache holds %d entries, want 91", len(cache.entries))
	}
}
