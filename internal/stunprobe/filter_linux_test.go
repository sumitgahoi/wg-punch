package stunprobe

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestFilter(t *testing.T) {
	raw, err := buildFilter(3478, 51820)
	if err != nil {
		t.Fatal(err)
	}

	// Run the exact assembled BPF program in Go's VM so the test covers
	// the same jump offsets and packet offsets that Linux will receive.
	instructions, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("could not disassemble BPF program")
	}

	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		sourcePort      uint16
		destinationPort uint16
		wantAccepted    bool
		ipHeaderLen     int
	}{
		{
			name:            "STUN response",
			sourcePort:      3478,
			destinationPort: 51820,
			wantAccepted:    true,
			ipHeaderLen:     20,
		},
		{
			name:            "wrong source port",
			sourcePort:      9999,
			destinationPort: 51820,
			wantAccepted:    false,
			ipHeaderLen:     20,
		},
		{
			name:            "wrong destination port",
			sourcePort:      3478,
			destinationPort: 9999,
			wantAccepted:    false,
			ipHeaderLen:     20,
		},
		{
			name:            "both ports wrong",
			sourcePort:      9999,
			destinationPort: 9999,
			wantAccepted:    false,
			ipHeaderLen:     20,
		},
		{
			name:            "STUN response with IPv4 options",
			sourcePort:      3478,
			destinationPort: 51820,
			wantAccepted:    true,
			ipHeaderLen:     24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := ipv4UDPPacket(tt.sourcePort, tt.destinationPort, tt.ipHeaderLen)

			n, err := vm.Run(packet)
			if err != nil {
				t.Fatal(err)
			}

			accepted := n != 0
			if accepted != tt.wantAccepted {
				t.Errorf(
					"accepted = %v, want %v",
					accepted,
					tt.wantAccepted,
				)
			}
		})
	}
}

func ipv4UDPPacket(sourcePort, destinationPort uint16, ipHeaderLen int) []byte {
	packet := make([]byte, ipHeaderLen+8)

	// IHL is stored as a count of 32-bit words in the low four bits
	// of the first IPv4 header byte.
	packet[0] = 0x40 | byte(ipHeaderLen/4)

	// Place the UDP header after the actual IPv4 header rather than
	// assuming the usual 20-byte header.
	packet[ipHeaderLen] = byte(sourcePort >> 8)
	packet[ipHeaderLen+1] = byte(sourcePort)
	packet[ipHeaderLen+2] = byte(destinationPort >> 8)
	packet[ipHeaderLen+3] = byte(destinationPort)

	return packet
}
