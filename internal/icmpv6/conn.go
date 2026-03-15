// Package icmpv6 provides a raw ICMPv6 Echo send/receive abstraction.
package icmpv6

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	ICMPv6TypeEchoRequest = 128
	ICMPv6TypeEchoReply   = 129
	// ICMPIdentifier is stamped in every ICMP echo packet so the receive
	// loop can filter out non-sshoi pings.
	ICMPIdentifier = 0x5348 // "SH"

	maxICMPPayload = 65507
	readBufSize    = 65535
)

// RawPacket is a received ICMPv6 packet with metadata.
type RawPacket struct {
	Src  net.IP
	Type byte   // 128 or 129
	Data []byte // ICMPv6 data field (tunnel payload)
}

// Conn wraps a raw ICMPv6 socket.
type Conn struct {
	pc      *ipv6.PacketConn
	recvBuf chan *RawPacket
	closed  chan struct{}
	once    sync.Once
}

// Listen opens a raw ICMPv6 socket. Requires CAP_NET_RAW / root.
// bufSize is the RawPacket channel capacity (suggested: 256).
func Listen(bufSize int) (*Conn, error) {
	// "ip6:ipv6-icmp" is the network string for raw ICMPv6.
	c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	pc := ipv6.NewPacketConn(c)
	conn := &Conn{
		pc:      pc,
		recvBuf: make(chan *RawPacket, bufSize),
		closed:  make(chan struct{}),
	}
	go conn.recvLoop()
	return conn, nil
}

// SendEchoRequest sends an ICMPv6 Echo Request (type 128) to dst.
func (c *Conn) SendEchoRequest(dst net.IP, data []byte) error {
	return c.send(ipv6.ICMPTypeEchoRequest, dst, data)
}

// SendEchoReply sends an ICMPv6 Echo Reply (type 129) to dst.
func (c *Conn) SendEchoReply(dst net.IP, data []byte) error {
	return c.send(ipv6.ICMPTypeEchoReply, dst, data)
}

// Recv returns the channel of received RawPackets.
func (c *Conn) Recv() <-chan *RawPacket { return c.recvBuf }

// Close shuts down the socket and stops the receive goroutine.
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.pc.Close()
	})
	return err
}

// send constructs and transmits an ICMPv6 echo packet.
func (c *Conn) send(msgType icmp.Type, dst net.IP, data []byte) error {
	if len(data) > maxICMPPayload {
		return errors.New("payload too large")
	}
	wire, err := buildICMPv6(msgType, data)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: dst}
	_, err = c.pc.WriteTo(wire, nil, addr)
	return err
}

// buildICMPv6 marshals an ICMPv6 echo message with our identifier.
func buildICMPv6(msgType icmp.Type, data []byte) ([]byte, error) {
	// Build echo body manually: ID(2) + Seq(2) + data
	body := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(body[0:2], ICMPIdentifier)
	binary.BigEndian.PutUint16(body[2:4], 0) // seq=0, tunnel seq is in payload
	copy(body[4:], data)

	msg := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}
	// Checksum is inserted by the kernel for IPv6; pass 0.
	return msg.Marshal(nil)
}

// recvLoop reads from the raw socket and pushes matching packets to recvBuf.
func (c *Conn) recvLoop() {
	buf := make([]byte, readBufSize)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		// Set a short read deadline so we can check c.closed periodically.
		_ = c.pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

		n, _, src, err := c.pc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-c.closed:
				return
			default:
				log.Printf("icmpv6: read error: %v", err)
				continue
			}
		}

		raw := buf[:n]
		pkt, err := parseICMPv6(raw, src)
		if err != nil {
			continue // not our packet or parse error
		}

		select {
		case c.recvBuf <- pkt:
		case <-c.closed:
			return
		default:
			// Drop if buffer full.
			log.Printf("icmpv6: recv buffer full, dropping packet")
		}
	}
}

// parseICMPv6 parses a raw ICMPv6 message and returns a RawPacket if it
// matches our identifier, otherwise returns an error.
func parseICMPv6(raw []byte, src net.Addr) (*RawPacket, error) {
	msg, err := icmp.ParseMessage(58 /* ICMPv6 proto */, raw)
	if err != nil {
		return nil, err
	}

	var msgType byte
	switch msg.Type {
	case ipv6.ICMPTypeEchoRequest:
		msgType = ICMPv6TypeEchoRequest
	case ipv6.ICMPTypeEchoReply:
		msgType = ICMPv6TypeEchoReply
	default:
		return nil, errors.New("not echo")
	}

	body, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, errors.New("not echo body")
	}

	if uint16(body.ID) != ICMPIdentifier {
		return nil, errors.New("wrong identifier")
	}

	// body.Data starts after the 4-byte echo header (ID+Seq); that's already
	// parsed into body.ID and body.Seq, so body.Data is pure tunnel payload.
	payload := make([]byte, len(body.Data))
	copy(payload, body.Data)

	var srcIP net.IP
	switch a := src.(type) {
	case *net.UDPAddr:
		srcIP = a.IP
	case *net.IPAddr:
		srcIP = a.IP
	}

	return &RawPacket{
		Src:  srcIP,
		Type: msgType,
		Data: payload,
	}, nil
}
