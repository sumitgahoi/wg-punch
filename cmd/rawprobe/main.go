package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pion/stun/v3"
	"golang.org/x/net/bpf"

	"golang.org/x/net/ipv4"
)

func main() {
	conn, err := net.ListenPacket("ip4:udp", "10.10.10.10")
	if err != nil {
		fmt.Println("open raw socket:", err)
		return
	}
	defer conn.Close()

	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadMemShift{Off: 0},
	
		// UDP source port must be 3478.
		bpf.LoadIndirect{Off: 0, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 3478, SkipTrue: 3},
	
		// UDP destination port must be our WireGuard port.
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 51820, SkipTrue: 1},
	
		bpf.RetConstant{Val: 0xffff}, // accept
		bpf.RetConstant{Val: 0},      // reject
	})

	if err != nil {
		fmt.Println("assemble filter:", err)
		return
	}
	packetConn := ipv4.NewPacketConn(conn)

	if err := packetConn.SetBPF(filter); err != nil {
		fmt.Println("attach filter:", err)
		return
	}

	fmt.Println("BPF filter attached")

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	payload := message.Raw

	packet := make([]byte, 8+len(payload))

	binary.BigEndian.PutUint16(packet[0:2], 51820)
	binary.BigEndian.PutUint16(packet[2:4], 3478)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], 0)

	copy(packet[8:], payload)

	dst := &net.IPAddr{IP: net.ParseIP("162.159.207.0")}

	_, err = conn.WriteTo(packet, dst)
	if err != nil {
		fmt.Println("send:", err)
		return
	}

	fmt.Println("sent raw UDP packet")

	buf := make([]byte, 1500)

	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		fmt.Println("receive:", err)
		return
	}

	fmt.Printf("received %d bytes from %v\n", n, from)
	fmt.Printf("raw: %x\n", buf[:n])

	response := new(stun.Message)
	response.Raw = buf[8:n]

	if err := response.Decode(); err != nil {
		fmt.Println("decode STUN:", err)
		return
	}

	if response.TransactionID != message.TransactionID {
		fmt.Printf(
			"transaction ID mismatch: sent %x, received %x\n",
			message.TransactionID,
			response.TransactionID,
		)
		return
	}
	
	fmt.Println("transaction ID matched")

	var mapped stun.XORMappedAddress

	if err := mapped.GetFrom(response); err != nil {
		fmt.Println("get XOR-MAPPED-ADDRESS:", err)
		return
	}

	fmt.Printf("public endpoint: %s:%d\n", mapped.IP, mapped.Port)
}
