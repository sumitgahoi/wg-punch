package stunprobe

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/pion/stun/v3"
)

func Discover(
	ctx context.Context,
	listenPort uint16,
	server string,
) (netip.AddrPort, error) {
	// Resolve the STUN server and ask Linux which local source address
	// it would use to reach that destination.
	localIP, remote, err := resolveRoute(server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve STUN route: %w", err)
	}

	// Send the STUN request from WireGuard's listen port and wait for
	// the response belonging to this exact transaction.
	response, err := probe(ctx, localIP, listenPort, remote)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("STUN probe: %w", err)
	}

	// The STUN server reports the public IP and port from which it saw
	// our request. For this project, that is our public WireGuard candidate.
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		return netip.AddrPort{}, fmt.Errorf("read XOR-MAPPED-ADDRESS: %w", err)
	}

	addr, ok := netip.AddrFromSlice(mapped.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("invalid mapped IP: %v", mapped.IP)
	}

	return netip.AddrPortFrom(addr, uint16(mapped.Port)), nil
}