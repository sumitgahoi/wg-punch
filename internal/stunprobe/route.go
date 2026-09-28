package stunprobe

import (
	"net"
	"net/netip"
)

func resolveRoute(server string) (netip.Addr, netip.AddrPort, error) {
	conn, err := net.Dial("udp4", server)
	if err != nil {
		return netip.Addr{}, netip.AddrPort{}, err
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.UDPAddr)
	remote := conn.RemoteAddr().(*net.UDPAddr)

	return local.AddrPort().Addr(), remote.AddrPort(), nil
}