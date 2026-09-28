package stunprobe

import (
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

func buildFilter(sourcePort, destinationPort uint16) ([]bpf.RawInstruction, error) {
	// Socket BPF sees the complete IPv4 packet. Compute the actual
	// IPv4 header length so this still works when IP options are present.
	instructions := []bpf.Instruction{
		bpf.LoadMemShift{Off: 0},

		// Only accept packets from the expected remote UDP port.
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.JumpIf{
			Cond:     bpf.JumpNotEqual,
			Val:      uint32(sourcePort),
			SkipTrue: 3,
		},

		// Only accept packets addressed to our local WireGuard port.
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{
			Cond:     bpf.JumpNotEqual,
			Val:      uint32(destinationPort),
			SkipTrue: 1,
		},

		bpf.RetConstant{Val: 0xffff}, // Deliver to our raw socket.
		bpf.RetConstant{Val: 0},      // Ignore on our raw socket.
	}

	return bpf.Assemble(instructions)
}

func attachFilter(conn *net.IPConn, filter []bpf.RawInstruction) error {
	// This is a socket filter: rejected packets are hidden only from
	// this raw socket. They are not dropped from the Linux networking
	// stack and still reach kernel WireGuard normally.
	packetConn := ipv4.NewPacketConn(conn)

	return packetConn.SetBPF(filter)
}