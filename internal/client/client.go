// Package client implements the sshoi tunnel client.
package client

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sshoi/sshoi/internal/icmpv6"
	"github.com/sshoi/sshoi/internal/tunnel"
)

// Config holds client startup parameters.
type Config struct {
	ListenAddr        string      // e.g. "127.0.0.1:2222"
	ServerAddr        *net.IPAddr // IPv6 address with Zone for link-local
	IfaceName         string      // outbound interface, e.g. "eth0"
	Cipher            *tunnel.Cipher
	KeepaliveInterval time.Duration
	RetransmitTimeout time.Duration
	WindowSize        uint32
}

// Client manages all active sessions.
type Client struct {
	cfg      Config
	conn     *icmpv6.Conn
	sessions sync.Map // map[uint16]*tunnel.Session
	nextID   uint32   // atomic, wraps at 65535
	outbound chan outboundMsg
	closed   chan struct{}
	once     sync.Once
}

type outboundMsg struct {
	dst  *net.IPAddr
	data []byte
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	conn, err := icmpv6.Listen(cfg.IfaceName, 256)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:      cfg,
		conn:     conn,
		outbound: make(chan outboundMsg, 512),
		closed:   make(chan struct{}),
	}, nil
}

// Run starts the TCP listener and ICMP loops. Blocks until Close is called.
func (c *Client) Run() error {
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("client: listening on %s", c.cfg.ListenAddr)
	log.Printf("client: tunnel server %s", c.cfg.ServerAddr)

	go c.icmpRecvLoop()
	go c.icmpSendLoop()

	go func() {
		<-c.closed
		ln.Close()
	}()

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			select {
			case <-c.closed:
				return nil
			default:
				log.Printf("client: accept error: %v", err)
				continue
			}
		}
		go c.newSession(tcpConn)
	}
}

// Close shuts down the client.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		c.sessions.Range(func(_, v interface{}) bool {
			v.(*tunnel.Session).Close()
			return true
		})
		err = c.conn.Close()
	})
	return err
}

// newSession allocates a session, starts it, and registers it.
func (c *Client) newSession(tcpConn net.Conn) {
	id := uint16(atomic.AddUint32(&c.nextID, 1) % 65535)
	if id == 0 {
		id = 1
	}

	sess := tunnel.NewSession(tunnel.SessionConfig{
		ID:                id,
		Cipher:            c.cfg.Cipher,
		TCPConn:           tcpConn,
		KeepaliveInterval: c.cfg.KeepaliveInterval,
		RetransmitTimeout: c.cfg.RetransmitTimeout,
		WindowSize:        c.cfg.WindowSize,
		IsServer:          false,
	})
	sess.StartEncodeLoop()
	c.sessions.Store(id, sess)
	log.Printf("client: new session %d for %s", id, tcpConn.RemoteAddr())

	go c.fanInSession(sess)

	go func() {
		<-sess.Done()
		c.sessions.Delete(id)
		log.Printf("client: session %d cleaned up", id)
	}()
}

// fanInSession forwards a session's wire packets to the shared outbound channel.
func (c *Client) fanInSession(sess *tunnel.Session) {
	for {
		select {
		case wire, ok := <-sess.SendWire:
			if !ok {
				return
			}
			select {
			case c.outbound <- outboundMsg{dst: c.cfg.ServerAddr, data: wire}:
			case <-c.closed:
				return
			case <-sess.Done():
				return
			}
		case <-sess.Done():
			return
		case <-c.closed:
			return
		}
	}
}

// icmpRecvLoop reads from the ICMPv6 socket and dispatches to sessions.
func (c *Client) icmpRecvLoop() {
	for {
		select {
		case pkt, ok := <-c.conn.Recv():
			if !ok {
				return
			}
			if pkt.Type != icmpv6.ICMPv6TypeEchoReply {
				continue
			}
			if len(pkt.Data) < tunnel.HeaderLen {
				continue
			}
			var hdr tunnel.Header
			if err := tunnel.DecodeHeader(pkt.Data, &hdr); err != nil {
				continue
			}
			v, ok := c.sessions.Load(hdr.SessionID)
			if !ok {
				log.Printf("client: unknown session %d, dropping", hdr.SessionID)
				continue
			}
			if err := v.(*tunnel.Session).ReceivePacket(pkt.Data); err != nil {
				log.Printf("client: session %d recv error: %v", hdr.SessionID, err)
			}
		case <-c.closed:
			return
		}
	}
}

// icmpSendLoop drains the shared outbound channel and sends Echo Requests.
func (c *Client) icmpSendLoop() {
	for {
		select {
		case msg := <-c.outbound:
			if err := c.conn.SendEchoRequest(msg.dst, msg.data); err != nil {
				log.Printf("client: send error: %v", err)
			}
		case <-c.closed:
			return
		}
	}
}
