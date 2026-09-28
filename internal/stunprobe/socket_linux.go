package stunprobe

import (
	"fmt"
	"net"
	"net/netip"
)

func openRawSocket(localIP netip.Addr) (*net.IPConn, error) {
	// Kernel WireGuard already owns its UDP listen port, so we cannot
	// bind another normal UDP socket to it. A raw UDP socket lets us
	// construct packets using that source port without claiming it.
	conn, err := net.ListenIP("ip4:udp", &net.IPAddr{
		IP: net.IP(localIP.AsSlice()),
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func sendDatagram(
	conn *net.IPConn,
	remote netip.AddrPort,
	datagram []byte,
) error {
	dst := &net.IPAddr{
		IP: net.IP(remote.Addr().AsSlice()),
	}

	n, err := conn.WriteToIP(datagram, dst)
	if err != nil {
		return err
	}

	if n != len(datagram) {
		return fmt.Errorf("short raw UDP write: wrote %d of %d bytes", n, len(datagram))
	}

	return nil
}