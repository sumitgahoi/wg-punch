package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func main() {
	client, err := wgctrl.New()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	devices, err := client.Devices()
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, device := range devices {
		fmt.Printf("%s: listen port %d\n", device.Name, device.ListenPort)
	}
}