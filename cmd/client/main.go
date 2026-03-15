package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sshoi/sshoi/internal/client"
	"github.com/sshoi/sshoi/internal/tunnel"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:2222", "Local TCP address to listen on")
	server := flag.String("server", "", "Server IPv6 address (required)")
	passphrase := flag.String("passphrase", "", "Shared passphrase (or set SSHOI_PASSPHRASE)")
	keepalive := flag.Duration("keepalive", 15*time.Second, "Keepalive interval")
	retransmit := flag.Duration("retransmit", 500*time.Millisecond, "Retransmit timeout")
	verbose := flag.Bool("v", false, "Verbose logging")
	flag.Parse()

	if !*verbose {
		log.SetFlags(log.LstdFlags)
	}

	if *server == "" {
		log.Fatal("client: -server is required")
	}

	serverIP := net.ParseIP(*server)
	if serverIP == nil {
		log.Fatalf("client: invalid server IPv6 address: %s", *server)
	}
	// Ensure it is actually an IPv6 address.
	if serverIP.To4() != nil {
		log.Fatalf("client: %s is an IPv4 address; an IPv6 address is required", *server)
	}

	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("SSHOI_PASSPHRASE")
	}
	if pass == "" {
		log.Fatal("client: passphrase required via -passphrase or SSHOI_PASSPHRASE env var")
	}

	cipher, err := tunnel.NewCipherFromPassphrase(pass)
	if err != nil {
		log.Fatalf("client: cipher setup: %v", err)
	}

	cfg := client.Config{
		ListenAddr:        *listen,
		ServerIPv6:        serverIP,
		Cipher:            cipher,
		KeepaliveInterval: *keepalive,
		RetransmitTimeout: *retransmit,
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("client: init failed: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("client: shutting down")
		c.Close()
	}()

	if err := c.Run(); err != nil {
		log.Fatalf("client: run error: %v", err)
	}
}
