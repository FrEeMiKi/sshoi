package tunnel

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"
)

// SessionState represents the lifecycle state of a tunnel session.
type SessionState int

const (
	StateNew        SessionState = iota
	StateHandshake               // SYN sent, waiting for SYN+ACK
	StateEstablished             // data flows freely
	StateClosing                 // FIN sent, draining
	StateClosed                  // done
)

func (s SessionState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateHandshake:
		return "HANDSHAKE"
	case StateEstablished:
		return "ESTABLISHED"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	}
	return "UNKNOWN"
}

// SessionConfig carries constructor parameters.
type SessionConfig struct {
	ID                uint16
	Cipher            *Cipher
	TCPConn           net.Conn // nil for server-side pre-establishment
	KeepaliveInterval time.Duration
	RetransmitTimeout time.Duration
	WindowSize        uint32
	// IsServer distinguishes server-side behaviour (waits for SYN) from client
	// (sends SYN on start).
	IsServer bool
}

// Session is one multiplexed tunnel session.
type Session struct {
	mu    sync.Mutex
	id    uint16
	state SessionState

	cipher    *Cipher
	sendQ     *SendQueue
	recvTrack *RecvTracker

	tcpConn net.Conn

	inbound  chan []byte // decrypted plaintext from remote → write to tcpConn
	outbound chan []byte // plaintext from tcpConn → encrypt and send
	SendWire chan []byte // fully encoded wire packets ready for ICMPv6 send

	closeOnce       sync.Once
	closed          chan struct{}
	// established is closed when the session reaches StateEstablished.
	// StartEncodeLoop blocks on this so DATA is never sent before the handshake.
	established     chan struct{}
	establishedOnce sync.Once

	lastActivity      time.Time
	keepaliveInterval time.Duration
	retransmitTimeout time.Duration
	isServer          bool
}

// NewSession constructs a Session and starts its goroutines.
func NewSession(cfg SessionConfig) *Session {
	ka := cfg.KeepaliveInterval
	if ka == 0 {
		ka = 15 * time.Second
	}
	rt := cfg.RetransmitTimeout
	if rt == 0 {
		rt = DefaultRetransmitTimeout
	}
	win := cfg.WindowSize
	if win == 0 {
		win = DefaultWindowSize
	}

	s := &Session{
		id:                cfg.ID,
		state:             StateNew,
		cipher:            cfg.Cipher,
		sendQ:             NewSendQueue(0, win),
		recvTrack:         NewRecvTracker(0),
		tcpConn:           cfg.TCPConn,
		inbound:           make(chan []byte, 32),
		outbound:          make(chan []byte, 32),
		SendWire:          make(chan []byte, 64),
		closed:            make(chan struct{}),
		established:       make(chan struct{}),
		lastActivity:      time.Now(),
		keepaliveInterval: ka,
		retransmitTimeout: rt,
		isServer:          cfg.IsServer,
	}

	if !cfg.IsServer {
		// Client: send SYN immediately.
		s.state = StateHandshake
		go func() {
			if err := s.sendControlPacket(FlagSYN); err != nil {
				log.Printf("session %d: SYN send failed: %v", s.id, err)
			}
		}()
	}

	if cfg.TCPConn != nil {
		go s.tcpReadLoop()
		go s.tcpWriteLoop()
	}
	go s.retransmitLoop()
	go s.keepaliveLoop()
	return s
}

// ID returns the session identifier.
func (s *Session) ID() uint16 { return s.id }

// State returns the current state.
func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// AttachTCPConn binds a TCP connection to the session (server-side post-SYN).
func (s *Session) AttachTCPConn(conn net.Conn) {
	s.mu.Lock()
	s.tcpConn = conn
	s.mu.Unlock()
	go s.tcpReadLoop()
	go s.tcpWriteLoop()
}

// ReceivePacket is called by the ICMPv6 receive loop to deliver a raw wire
// blob. It decodes, decrypts, and dispatches the packet.
func (s *Session) ReceivePacket(raw []byte) error {
	h, nonce, ciphertext, err := DecodeOuter(raw)
	if err != nil {
		return err
	}

	aad := raw[:HeaderLen]
	plaintext, err := s.cipher.Open(nonce, ciphertext, aad)
	if err != nil {
		return err
	}

	pkt := &Packet{
		Header:  h,
		Nonce:   nonce,
		Payload: plaintext,
	}

	// Sequence tracking is only applied to DATA packets.
	// Control packets (SYN, ACK, FIN, KA) all use seq=0 and must NOT be
	// fed into recvTrack — otherwise the first DATA packet (also seq=0)
	// would be rejected as a duplicate.
	if h.Flags&FlagDATA != 0 {
		s.mu.Lock()
		isNew, _ := s.recvTrack.Receive(h.Seq)
		s.mu.Unlock()
		if !isNew {
			return nil // duplicate data packet
		}
	}

	s.lastActivity = time.Now()
	s.handleFlags(pkt)
	return nil
}

// Close initiates an orderly shutdown.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.state != StateClosed {
			s.state = StateClosing
		}
		s.mu.Unlock()

		_ = s.sendControlPacket(FlagFIN | FlagACK)

		s.mu.Lock()
		s.state = StateClosed
		if s.tcpConn != nil {
			s.tcpConn.Close()
		}
		s.mu.Unlock()

		close(s.closed)
		log.Printf("session %d: closed", s.id)
	})
}

// Done returns a channel closed when the session reaches StateClosed.
func (s *Session) Done() <-chan struct{} { return s.closed }

// markEstablished transitions to StateEstablished and unblocks StartEncodeLoop.
// Safe to call multiple times.
func (s *Session) markEstablished() {
	s.mu.Lock()
	s.state = StateEstablished
	s.mu.Unlock()
	s.establishedOnce.Do(func() { close(s.established) })
}

// handleFlags drives state transitions based on received packet flags.
func (s *Session) handleFlags(pkt *Packet) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()

	flags := pkt.Flags

	switch {
	case flags&FlagSYN != 0 && flags&FlagACK != 0:
		// SYN+ACK: client receives this during handshake.
		if state == StateHandshake {
			s.markEstablished()
			log.Printf("session %d: established", s.id)
			_ = s.sendControlPacket(FlagACK)
		}

	case flags&FlagSYN != 0:
		// SYN: server receives this for a new session.
		if state == StateNew {
			s.markEstablished()
			log.Printf("session %d: established (server)", s.id)
			_ = s.sendControlPacket(FlagSYN | FlagACK)
		}

	case flags&FlagFIN != 0:
		// Remote closed.
		log.Printf("session %d: received FIN", s.id)
		go s.Close()

	case flags&FlagKA != 0:
		// Keepalive — just ACK.
		_ = s.sendControlPacket(FlagACK)

	case flags&FlagACK != 0 && flags&FlagDATA == 0:
		// Pure ACK — advance send window.
		s.mu.Lock()
		s.sendQ.Acknowledge(pkt.Ack)
		s.mu.Unlock()

	case flags&FlagDATA != 0:
		// Data packet — advance our send window then ACK immediately.
		// Without the ACK the sender would retransmit until it hits
		// MaxRetransmitAttempts (causing the "max retransmit exceeded"
		// close) whenever the session is idle and no DATA is flowing in
		// the reverse direction to piggyback an ACK.
		s.mu.Lock()
		s.sendQ.Acknowledge(pkt.Ack)
		s.mu.Unlock()
		go func() { _ = s.sendControlPacket(FlagACK) }()
		if len(pkt.Payload) > 0 {
			log.Printf("session %d: DATA rx seq=%d ack=%d len=%d", s.id, pkt.Seq, pkt.Ack, len(pkt.Payload))
			select {
			case s.inbound <- pkt.Payload:
			case <-s.closed:
			}
		}
	}
}

// sendControlPacket builds and enqueues a control packet (SYN/FIN/ACK/KA)
// with no payload.
//
// Rules:
//   - Seq is always 0. Control packets do not consume the DATA sequence space.
//   - Ack is recvTrack.NextExpected() — reflects how many DATA packets from
//     the remote side have been received (0 when none). Since Acknowledge uses
//     strict less-than, ack=0 removes nothing from the peer's retransmit queue,
//     so a handshake ACK cannot prematurely evict unreceived data packets.
func (s *Session) sendControlPacket(flags byte) error {
	s.mu.Lock()
	ack := s.recvTrack.NextExpected()
	s.mu.Unlock()

	hdr := Header{
		SessionID:  s.id,
		Seq:        0,
		Ack:        ack,
		Flags:      flags,
		PayloadLen: 0,
	}

	return s.buildAndEnqueue(hdr, nil)
}

// buildAndEnqueue encrypts a packet and pushes it onto SendWire.
func (s *Session) buildAndEnqueue(hdr Header, plaintext []byte) error {
	// Build the header bytes for AAD.
	aadBuf := make([]byte, HeaderLen)
	if err := EncodeHeader(aadBuf, hdr); err != nil {
		return err
	}

	nonce, ciphertext, err := s.cipher.Seal(plaintext, aadBuf)
	if err != nil {
		return err
	}

	wire, err := EncodePlaintext(hdr, nonce, ciphertext)
	if err != nil {
		return err
	}

	// For data packets, track in sendQ.
	if hdr.Flags&FlagDATA != 0 {
		s.mu.Lock()
		_, err = s.sendQ.Enqueue(wire)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}

	select {
	case s.SendWire <- wire:
	case <-s.closed:
	}
	return nil
}

// tcpReadLoop reads from the TCP connection and feeds outbound.
func (s *Session) tcpReadLoop() {
	buf := make([]byte, MaxPayload)
	for {
		s.mu.Lock()
		conn := s.tcpConn
		s.mu.Unlock()
		if conn == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}

		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-s.closed:
			default:
				log.Printf("session %d: closing — tcp read error: %v", s.id, err)
				go s.Close()
			}
			return
		}

		chunk := make([]byte, n)
		copy(chunk, buf[:n])

		select {
		case s.outbound <- chunk:
		case <-s.closed:
			return
		}
	}
}

// tcpWriteLoop writes inbound data to the TCP connection.
func (s *Session) tcpWriteLoop() {
	for {
		select {
		case data := <-s.inbound:
			s.mu.Lock()
			conn := s.tcpConn
			s.mu.Unlock()
			if conn == nil {
				continue
			}
			if _, err := conn.Write(data); err != nil {
				select {
				case <-s.closed:
				default:
					log.Printf("session %d: closing — tcp write error: %v", s.id, err)
					go s.Close()
				}
				return
			}
		case <-s.closed:
			return
		}
	}
}

// encodeLoop is started by the client/server send path. It reads from
// outbound, builds encrypted data packets, and pushes them onto SendWire.
// This goroutine is started externally after session establishment.
func (s *Session) StartEncodeLoop() {
	go func() {
		// Block until the handshake completes. This prevents DATA packets
		// from being sent before the server has seen a SYN for this session.
		select {
		case <-s.established:
		case <-s.closed:
			return
		}
		for {
			select {
			case chunk := <-s.outbound:
				s.mu.Lock()
				seq := s.sendQ.PeekNext()
				ack := s.recvTrack.NextExpected()
				s.mu.Unlock()

				hdr := Header{
					SessionID:  s.id,
					Seq:        seq,
					Ack:        ack,
					Flags:      FlagDATA | FlagACK,
					PayloadLen: uint16(len(chunk)),
				}

				if err := s.buildAndEnqueue(hdr, chunk); err != nil {
					log.Printf("session %d: encode error: %v", s.id, err)
				}
			case <-s.closed:
				return
			}
		}
	}()
}

// retransmitLoop retransmits timed-out packets.
func (s *Session) retransmitLoop() {
	ticker := time.NewTicker(s.retransmitTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			timedOut := s.sendQ.TimedOut(s.retransmitTimeout)
			s.mu.Unlock()

			for _, e := range timedOut {
				e.Attempts++
				e.SentAt = time.Now()
				if e.Attempts > MaxRetransmitAttempts {
					log.Printf("session %d: max retransmit exceeded, closing", s.id)
					go s.Close()
					return
				}
				select {
				case s.SendWire <- e.Data:
				case <-s.closed:
					return
				}
			}
		case <-s.closed:
			return
		}
	}
}

// keepaliveLoop sends periodic KA packets.
func (s *Session) keepaliveLoop() {
	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			state := s.state
			s.mu.Unlock()
			if state != StateEstablished {
				continue
			}
			if err := s.sendControlPacket(FlagKA); err != nil {
				log.Printf("session %d: keepalive failed: %v", s.id, err)
			}
		case <-s.closed:
			return
		}
	}
}

// seqFromPayload extracts the 32-bit seq from a wire packet's SEQ field for
// logging purposes without full decode.
func seqFromPayload(wire []byte) uint32 {
	if len(wire) < 10 {
		return 0
	}
	return binary.BigEndian.Uint32(wire[6:10])
}
