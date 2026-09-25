package netfilter

import (
	"net"
	"net/netip"
)

// LocalNetworks returns the IPv4 networks of this host's interfaces, loopback
// included. Traffic to them does not need an upstream proxy.
func LocalNetworks() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var networks []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, _ := netip.AddrFromSlice(ipNet.IP)
		ones, _ := ipNet.Mask.Size()
		if addr = addr.Unmap(); addr.Is4() {
			networks = append(networks, netip.PrefixFrom(addr, ones).Masked())
		}
	}
	return networks, nil
}
