package stunprobe

import (
	"context"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

// IPv4's 16-bit Total Length field limits a complete IPv4 packet
// to 65,535 bytes. This avoids assuming a particular link MTU.
const maxIPv4PacketSize = 65_535

func receiveResponse(
	ctx context.Context,
	conn *net.IPConn,
	transactionID [stun.TransactionIDSize]byte,
) (*stun.Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// ReadFromIP is a blocking kernel call. Context cancellation does not
	// interrupt it automatically, so force the read to wake when ctx ends.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
	})
	defer stop()

	buf := make([]byte, maxIPv4PacketSize)

	for {
		n, _, err := conn.ReadFromIP(buf)
		if err != nil {
			// If context cancellation caused the read deadline above,
			// return the context's actual error rather than a socket timeout.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			return nil, err
		}

		// A raw IPv4 UDP socket gives us the UDP header followed by its
		// payload. We need at least the 8-byte UDP header before STUN begins.
		if n <= 8 {
			continue
		}

		response := new(stun.Message)
		response.Raw = buf[8:n]

		// The BPF filter narrows packets by UDP ports, but it does not prove
		// the payload is STUN. Ignore anything Pion cannot decode as STUN.
		if err := response.Decode(); err != nil {
			continue
		}

		// Another STUN transaction could use the same ports. Only return the
		// response belonging to the request that this probe actually sent.
		if response.TransactionID != transactionID {
			continue
		}

		return response, nil
	}
}