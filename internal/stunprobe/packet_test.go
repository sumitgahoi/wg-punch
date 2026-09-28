package stunprobe

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBuildDatagram(t *testing.T) {
	localIP := netip.MustParseAddr("10.10.10.10")
	remote := netip.MustParseAddrPort("162.159.207.0:3478")
	payload := []byte("hello")

	datagram, err := buildDatagram(localIP, 51820, remote, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Decode the bytes we produced instead of checking their raw hex.
	// This verifies the packet's meaning rather than its representation.
	packet := gopacket.NewPacket(datagram, layers.LayerTypeUDP, gopacket.Default)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("UDP layer not found")
	}

	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		t.Fatal("decoded UDP layer has unexpected type")
	}

	if udp.SrcPort != 51820 {
		t.Errorf("source port = %d, want 51820", udp.SrcPort)
	}

	if udp.DstPort != 3478 {
		t.Errorf("destination port = %d, want 3478", udp.DstPort)
	}

	if udp.Length != 8+uint16(len(payload)) {
		t.Errorf("UDP length = %d, want %d", udp.Length, 8+len(payload))
	}

	if !bytes.Equal(udp.Payload, payload) {
		t.Errorf("payload = %q, want %q", udp.Payload, payload)
	}
}
