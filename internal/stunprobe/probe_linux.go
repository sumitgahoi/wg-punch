package stunprobe

import (
	"context"
	"net/netip"

	"github.com/pion/stun/v3"
)

func probe(
	ctx context.Context,
	localIP netip.Addr,
	sourcePort uint16,
	remote netip.AddrPort,
) (*stun.Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Create a STUN Binding Request with a fresh transaction ID.
	// We keep the request so the eventual response can be matched
	// against this exact transaction.
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Construct a UDP datagram whose source port is WireGuard's listen
	// port. This does not bind or take ownership of that UDP port.
	datagram, err := buildDatagram(
		localIP,
		sourcePort,
		remote,
		request.Raw,
	)
	if err != nil {
		return nil, err
	}

	conn, err := openRawSocket(localIP)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Only copy plausible STUN responses to our raw socket. Rejected
	// packets continue through the kernel normally, including to WireGuard.
	filter, err := buildFilter(remote.Port(), sourcePort)
	if err != nil {
		return nil, err
	}

	if err := attachFilter(conn, filter); err != nil {
		return nil, err
	}

	if err := sendDatagram(conn, remote, datagram); err != nil {
		return nil, err
	}

	// Receiving and validating the matching response comes next.
	return receiveResponse(ctx, conn, request.TransactionID)
}