package stunprobe

import (
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func buildDatagram(
	localIP netip.Addr,
	sourcePort uint16,
	remote netip.AddrPort,
	payload []byte,
) ([]byte, error) {
	// UDP checksums include a pseudo-header containing the source and
	// destination IPs, so GoPacket needs the IP layer even though we
	// are only serializing the UDP datagram below.
	ip := &layers.IPv4{
		SrcIP:    net.IP(localIP.AsSlice()),
		DstIP:    net.IP(remote.Addr().AsSlice()),
		Protocol: layers.IPProtocolUDP,
	}

	// This source port may already belong to kernel WireGuard.
	// We are constructing a UDP datagram, not binding a UDP socket,
	// so using WireGuard's listen port here does not claim the port.
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sourcePort),
		DstPort: layers.UDPPort(remote.Port()),
	}

	// Associate the UDP layer with the IP pseudo-header so GoPacket
	// can calculate the correct UDP checksum.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()

	// Serialize the UDP header and payload. GoPacket calculates both
	// the UDP length and checksum for us.
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		udp,
		gopacket.Payload(payload),
	)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}