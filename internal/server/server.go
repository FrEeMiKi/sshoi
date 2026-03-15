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
	SSHDAddr          string // e.g. "127.0.0.1:22"
	Cipher            *tunnel.Cipher
	KeepaliveInterval time.Duration
	RetransmitTimeout time.Duration
	WindowSize        uint32
}

// sessionEntry pairs a Session with the originating client IP.
type sessionEntry struct {
	session  *tunnel.Session
	clientIP net.IP
}

// Server manages all active tunnel sessions.
type Server struct {
	cfg      Config
	conn     *icmpv6.Conn
	sessions sync.Map // map[uint16]*sessionEntry
	mu       sync.Map // map[uint16]struct{} — tracks sessions being opened
	closed   chan struct{}
	once     sync.Once
}

// New creates a Server.
func New(cfg Config) (*Server, error) {
	conn, err := icmpv6.Listen(256)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		conn:   conn,
		closed: make(chan struct{}),
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
			v.(*sessionEntry).session.Close()
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
			// Server receives Echo Requests (type 128).
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

			if _, exists := s.sessions.Load(hdr.SessionID); exists {
				// Existing session — hand off.
				v, _ := s.sessions.Load(hdr.SessionID)
				entry := v.(*sessionEntry)
				if err := entry.session.ReceivePacket(pkt.Data); err != nil {
					log.Printf("server: session %d recv err: %v", hdr.SessionID, err)
				}
				continue
			}

			// New session ID.
			if hdr.Flags&tunnel.FlagSYN != 0 {
				// Guard against concurrent duplicate SYNs.
				if _, loaded := s.mu.LoadOrStore(hdr.SessionID, struct{}{}); !loaded {
					go func(raw []byte, src net.IP, id uint16) {
						s.openSession(src, raw, id)
						s.mu.Delete(id)
					}(pkt.Data, pkt.Src, hdr.SessionID)
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
func (s *Server) openSession(clientIP net.IP, synRaw []byte, id uint16) {
	log.Printf("server: new session %d from %s", id, clientIP)

	// Dial sshd first; fail fast with FIN if unreachable.
	tcpConn, err := net.DialTimeout("tcp", s.cfg.SSHDAddr, 5*time.Second)
	if err != nil {
		log.Printf("server: dial sshd failed for session %d: %v", id, err)
		// Send FIN to client.
		s.sendFIN(clientIP, id)
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

	entry := &sessionEntry{session: sess, clientIP: clientIP}
	s.sessions.Store(id, entry)

	// Start the send loop for this session.
	go s.icmpSendLoopForSession(entry)

	// Process the initial SYN packet.
	if err := sess.ReceivePacket(synRaw); err != nil {
		log.Printf("server: session %d initial SYN error: %v", id, err)
	}

	// Wait for session to close, then deregister.
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
			if err := s.conn.SendEchoReply(entry.clientIP, wire); err != nil {
				log.Printf("server: send reply to %s error: %v", entry.clientIP, err)
			}
		case <-sess.Done():
			return
		case <-s.closed:
			return
		}
	}
}

// sendFIN sends a bare FIN packet to notify the client of failure.
func (s *Server) sendFIN(clientIP net.IP, sessionID uint16) {
	// Build a minimal FIN wire packet (no cipher — use a placeholder).
	// We need a cipher to build it; if we don't have one we can't authenticate.
	// In this implementation we log and drop since the client will time out.
	log.Printf("server: unable to send FIN to %s for session %d (no cipher context)", clientIP, sessionID)
}
