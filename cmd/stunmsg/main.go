package main

import (
	"fmt"

	"github.com/pion/stun/v3"
)

func main() {
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	fmt.Printf("length: %d bytes\n", len(message.Raw))
	fmt.Printf("transaction ID: %x\n", message.TransactionID)
	fmt.Printf("raw: %x\n", message.Raw)
}