//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/server"
)

func main() {
	port := flag.Int("port", config.DefaultPort, "Listen port")
	key := flag.String("key", "", "Pre-shared key for authentication")
	flag.Parse()

	if *key == "" {
		log.Fatal("Pre-shared key is required: -key <SECRET>")
	}

	if os.Geteuid() != 0 {
		log.Fatal("Root privileges required: sudo ./server")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := server.New(uint16(*port), []byte(*key))

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
