package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sshoi/sshoi/internal/server"
	"github.com/sshoi/sshoi/internal/tunnel"
)

func main() {
	sshdAddr := flag.String("sshd", "127.0.0.1:22", "Local sshd address to relay to")
	passphrase := flag.String("passphrase", "", "Shared passphrase (or set SSHOI_PASSPHRASE)")
	keepalive := flag.Duration("keepalive", 15*time.Second, "Keepalive interval")
	retransmit := flag.Duration("retransmit", 500*time.Millisecond, "Retransmit timeout")
	verbose := flag.Bool("v", false, "Verbose logging")
	flag.Parse()

	if !*verbose {
		log.SetFlags(log.LstdFlags)
	}

	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("SSHOI_PASSPHRASE")
	}
	if pass == "" {
		log.Fatal("server: passphrase required via -passphrase or SSHOI_PASSPHRASE env var")
	}

	cipher, err := tunnel.NewCipherFromPassphrase(pass)
	if err != nil {
		log.Fatalf("server: cipher setup: %v", err)
	}

	cfg := server.Config{
		SSHDAddr:          *sshdAddr,
		Cipher:            cipher,
		KeepaliveInterval: *keepalive,
		RetransmitTimeout: *retransmit,
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server: init failed: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("server: shutting down")
		srv.Close()
		os.Exit(0)
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("server: run error: %v", err)
	}
}
