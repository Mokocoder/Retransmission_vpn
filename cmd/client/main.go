//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"retransmission-vpn/internal/client"
	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/netutil"
)

func main() {
	serverAddr := flag.String("server", "", "VPN server IP address")
	port := flag.Int("port", config.DefaultPort, "VPN server port")
	key := flag.String("key", "", "Pre-shared key for authentication")
	flag.Parse()

	if *serverAddr == "" {
		if flag.NArg() > 0 {
			*serverAddr = flag.Arg(0)
		} else {
			fmt.Println("Usage: client -server <SERVER_IP> [-port PORT] [-key SECRET]")
			os.Exit(1)
		}
	}

	serverIP := net.ParseIP(*serverAddr)
	if serverIP == nil {
		log.Fatalf("Invalid server IP: %s", *serverAddr)
	}

	if *key == "" {
		log.Fatal("Pre-shared key is required: -key <SECRET>")
	}

	if !netutil.IsAdmin() {
		log.Fatal("Administrator privileges required")
	}

	log.Println("TCP Retransmission Tunnel - Client")
	log.Println("===================================")

	vpn := client.New(serverIP, uint16(*port), []byte(*key),
		client.WithStatusCallback(func(status string) {
			log.Println(status)
		}),
	)

	if err := vpn.Start(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
	defer vpn.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}
