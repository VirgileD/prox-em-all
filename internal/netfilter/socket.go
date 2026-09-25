package netfilter

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Dialer returns a dialer whose sockets carry mark, so that iptables does not
// redirect their traffic back to the proxy. Setting a mark requires the
// CAP_NET_ADMIN capability.
func Dialer(mark int) *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, _ string, conn syscall.RawConn) error {
			var err error
			controlErr := conn.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			})
			if controlErr != nil {
				return controlErr
			}
			return err
		},
	}
}

// OriginalDestination returns the address a TCP connection redirected by
// iptables was originally sent to.
func OriginalDestination(conn *net.TCPConn) (netip.AddrPort, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	// SO_ORIGINAL_DST returns a struct sockaddr_in. x/sys has no getsockopt for
	// it, but IPv6Mreq is a large enough byte array to receive it.
	var sockaddr *unix.IPv6Mreq
	var sockoptErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		sockaddr, sockoptErr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
	})
	if controlErr != nil {
		return netip.AddrPort{}, controlErr
	}
	if sockoptErr != nil {
		return netip.AddrPort{}, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", sockoptErr)
	}
	// struct sockaddr_in: 2 bytes of address family, 2 bytes of port and
	// 4 bytes of IPv4 address, both in network byte order.
	port := binary.BigEndian.Uint16(sockaddr.Multiaddr[2:4])
	addr := netip.AddrFrom4([4]byte(sockaddr.Multiaddr[4:8]))
	return netip.AddrPortFrom(addr, port), nil
}
