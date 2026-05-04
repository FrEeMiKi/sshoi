// Package server implements the sshoi tunnel server.
package server

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/sshoi/sshoi/internal/icmpv6"
	"github.com/sshoi/sshoi/internal/tunnel"
)

// Config holds server startup parameters.
type Config struct {
	IfaceName         string // outbound interface, e.g. "eth0"
	SSHDAddr          string // e.g. "127.0.0.1:22"
	Cipher            *tunnel.Cipher
	KeepaliveInterval time.Duration
	RetransmitTimeout time.Duration
	WindowSize        uint32
}

// sessionEntry pairs a Session with the originating client address.
// clientAddr preserves the Zone so replies to link-local addresses are routed
// to the correct interface.
type sessionEntry struct {
	session    *tunnel.Session
	clientAddr *net.IPAddr // includes Zone for fe80:: addresses
}

const maxConcurrentOpening = 100

// Server manages all active tunnel sessions.
type Server struct {
	cfg        Config
	conn       *icmpv6.Conn
	sessions   sync.Map    // map[uint16]*sessionEntry
	opening    sync.Map    // map[uint16]struct{} — guards against duplicate SYNs
	openingSem chan struct{} // limits concurrent session-open goroutines
	closed     chan struct{}
	once       sync.Once
}

// New creates a Server.
func New(cfg Config) (*Server, error) {
	conn, err := icmpv6.Listen(cfg.IfaceName, 256)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:        cfg,
		conn:       conn,
		openingSem: make(chan struct{}, maxConcurrentOpening),
		closed:     make(chan struct{}),
	}, nil
}

// Run starts the ICMP receive loop. Blocks until Close is called.
func (s *Server) Run() error {
	log.Printf("server: listening for ICMPv6, relaying SSH to %s", s.cfg.SSHDAddr)
	s.icmpRecvLoop()
	return nil
}

// Close shuts down the server.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		s.sessions.Range(func(_, v interface{}) bool {
			if entry, ok := v.(*sessionEntry); ok {
				entry.session.Close()
			}
			return true
		})
		err = s.conn.Close()
	})
	return err
}

// icmpRecvLoop is the main dispatch loop.
func (s *Server) icmpRecvLoop() {
	for {
		select {
		case pkt, ok := <-s.conn.Recv():
			if !ok {
				return
			}
			if pkt.Type != icmpv6.ICMPv6TypeEchoRequest {
				continue
			}
			if len(pkt.Data) < tunnel.HeaderLen {
				continue
			}

			var hdr tunnel.Header
			if err := tunnel.DecodeHeader(pkt.Data, &hdr); err != nil {
				continue
			}

			if v, exists := s.sessions.Load(hdr.SessionID); exists {
				entry, ok := v.(*sessionEntry)
				if !ok {
					continue
				}
				if err := entry.session.ReceivePacket(pkt.Data); err != nil {
					log.Printf("server: session %d recv err: %v", hdr.SessionID, err)
				}
				continue
			}

			if hdr.Flags&tunnel.FlagSYN != 0 {
				if _, loaded := s.opening.LoadOrStore(hdr.SessionID, struct{}{}); !loaded {
					select {
					case s.openingSem <- struct{}{}:
					default:
						log.Printf("server: concurrent open limit reached, dropping SYN for session %d", hdr.SessionID)
						s.opening.Delete(hdr.SessionID)
						continue
					}
					raw := make([]byte, len(pkt.Data))
					copy(raw, pkt.Data)
					src := pkt.Src
					id := hdr.SessionID
					go func() {
						defer func() { <-s.openingSem }()
						s.openSession(src, raw, id)
						s.opening.Delete(id)
					}()
				}
			} else {
				log.Printf("server: unknown session %d (no SYN), dropping", hdr.SessionID)
			}

		case <-s.closed:
			return
		}
	}
}

// openSession handles the first SYN for a new session.
func (s *Server) openSession(clientAddr *net.IPAddr, synRaw []byte, id uint16) {
	log.Printf("server: new session %d from %s", id, clientAddr)

	tcpConn, err := net.DialTimeout("tcp", s.cfg.SSHDAddr, 5*time.Second)
	if err != nil {
		log.Printf("server: dial sshd failed for session %d: %v", id, err)
		return
	}

	sess := tunnel.NewSession(tunnel.SessionConfig{
		ID:                id,
		Cipher:            s.cfg.Cipher,
		KeepaliveInterval: s.cfg.KeepaliveInterval,
		RetransmitTimeout: s.cfg.RetransmitTimeout,
		WindowSize:        s.cfg.WindowSize,
		IsServer:          true,
	})
	sess.AttachTCPConn(tcpConn)
	sess.StartEncodeLoop()

	entry := &sessionEntry{session: sess, clientAddr: clientAddr}
	s.sessions.Store(id, entry)

	go s.icmpSendLoopForSession(entry)

	if err := sess.ReceivePacket(synRaw); err != nil {
		log.Printf("server: session %d initial SYN error: %v", id, err)
	}

	<-sess.Done()
	s.sessions.Delete(id)
	log.Printf("server: session %d cleaned up", id)
}

// icmpSendLoopForSession drains a session's SendWire and sends Echo Replies.
func (s *Server) icmpSendLoopForSession(entry *sessionEntry) {
	sess := entry.session
	for {
		select {
		case wire, ok := <-sess.SendWire:
			if !ok {
				return
			}
			if err := s.conn.SendEchoReply(entry.clientAddr, wire); err != nil {
				log.Printf("server: send reply to %s error: %v", entry.clientAddr, err)
			}
		case <-sess.Done():
			return
		case <-s.closed:
			return
		}
	}
}
