package main

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func main() {
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP("10.10.10.10"),
		DstIP:    net.ParseIP("162.159.207.0"),
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 51820,
		DstPort: 3478,
	}

	payload := []byte("hello")

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}

	buf := gopacket.NewSerializeBuffer()

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
		panic(err)
	}

	fmt.Printf("UDP datagram: %x\n", buf.Bytes())
}