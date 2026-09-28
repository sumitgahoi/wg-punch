package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("udp4", "stun.cloudflare.com:3478")
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer conn.Close()

	fmt.Println("local:", conn.LocalAddr())
	fmt.Println("remote:", conn.RemoteAddr())
}