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
	iface := flag.String("iface", "", "Network interface for ICMPv6 (required for link-local, e.g. eth0)")
	passphrase := flag.String("passphrase", "", "Shared passphrase (or set SSHOI_PASSPHRASE)")
	keepalive := flag.Duration("keepalive", 15*time.Second, "Keepalive interval")
	retransmit := flag.Duration("retransmit", 500*time.Millisecond, "Retransmit timeout")
	flag.Parse()

	if *server == "" {
		log.Fatal("client: -server is required")
	}

	serverIP := net.ParseIP(*server)
	if serverIP == nil {
		log.Fatalf("client: invalid IPv6 address: %s", *server)
	}
	if serverIP.To4() != nil {
		log.Fatalf("client: %s is IPv4; an IPv6 address is required", *server)
	}

	// For link-local addresses the interface MUST be specified so the kernel
	// knows which interface to send on.
	if serverIP.IsLinkLocalUnicast() && *iface == "" {
		log.Fatal("client: -iface is required when -server is a link-local (fe80::) address")
	}

	serverAddr := &net.IPAddr{IP: serverIP, Zone: *iface}

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
		ServerAddr:        serverAddr,
		IfaceName:         *iface,
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
