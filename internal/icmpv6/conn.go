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
	// ICMPRequestID is stamped in Echo Requests (client→server).
	ICMPRequestID = 0x5348 // "SH"
	// ICMPReplyID is stamped in Echo Replies (server→client).
	// Using a different ID from ICMPRequestID lets the client filter out
	// kernel-generated auto-replies: the Linux kernel echoes back Echo
	// Requests with the same ID (0x5348), so the client only accepts
	// replies with ID 0x5349 — rejecting the kernel echoes.
	ICMPReplyID = 0x5349 // "SI"

	maxICMPPayload = 65507
	readBufSize    = 65535
)

// RawPacket is a received ICMPv6 packet with metadata.
// Src is a full IPAddr so the Zone (interface name) is preserved for
// link-local addresses — without the Zone, replies to fe80:: cannot be routed.
type RawPacket struct {
	Src  *net.IPAddr // Zone is set for link-local sources
	Type byte        // 128 or 129
	Data []byte      // ICMPv6 data field (tunnel payload)
}

// Conn wraps a raw ICMPv6 socket.
type Conn struct {
	pc       *ipv6.PacketConn
	ifaceName string // used as Zone when sending to link-local destinations
	recvBuf  chan *RawPacket
	closed   chan struct{}
	once     sync.Once
}

// Listen opens a raw ICMPv6 socket. Requires CAP_NET_RAW / root.
// ifaceName is the outbound interface (e.g. "eth0") used when sending to
// link-local (fe80::) addresses. Pass "" to skip zone tagging.
// bufSize is the RawPacket channel capacity (suggested: 256).
func Listen(ifaceName string, bufSize int) (*Conn, error) {
	c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	pc := ipv6.NewPacketConn(c)
	conn := &Conn{
		pc:        pc,
		ifaceName: ifaceName,
		recvBuf:   make(chan *RawPacket, bufSize),
		closed:    make(chan struct{}),
	}
	go conn.recvLoop()
	return conn, nil
}

// SendEchoRequest sends an ICMPv6 Echo Request (type 128) to dst.
// dst.Zone is used directly; if empty and the address is link-local,
// the Conn's ifaceName is substituted.
func (c *Conn) SendEchoRequest(dst *net.IPAddr, data []byte) error {
	return c.send(ipv6.ICMPTypeEchoRequest, c.resolveZone(dst), data)
}

// SendEchoReply sends an ICMPv6 Echo Reply (type 129) to dst.
func (c *Conn) SendEchoReply(dst *net.IPAddr, data []byte) error {
	return c.send(ipv6.ICMPTypeEchoReply, c.resolveZone(dst), data)
}

// resolveZone returns dst with Zone filled in from ifaceName when the
// address is link-local and no explicit zone is set.
func (c *Conn) resolveZone(dst *net.IPAddr) *net.IPAddr {
	if dst.Zone == "" && dst.IP.IsLinkLocalUnicast() && c.ifaceName != "" {
		return &net.IPAddr{IP: dst.IP, Zone: c.ifaceName}
	}
	return dst
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
// Echo Requests use ICMPRequestID; Echo Replies use ICMPReplyID.
func (c *Conn) send(msgType icmp.Type, dst *net.IPAddr, data []byte) error {
	if len(data) > maxICMPPayload {
		return errors.New("payload too large")
	}
	id := uint16(ICMPReplyID)
	if msgType == ipv6.ICMPTypeEchoRequest {
		id = ICMPRequestID
	}
	wire, err := buildICMPv6(msgType, id, data)
	if err != nil {
		return err
	}
	_, err = c.pc.WriteTo(wire, nil, dst)
	return err
}

// buildICMPv6 marshals an ICMPv6 echo message with the given identifier.
func buildICMPv6(msgType icmp.Type, id uint16, data []byte) ([]byte, error) {
	// Echo body: ID(2) + Seq(2) + tunnel payload
	body := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], 0) // ICMP seq=0; tunnel seq is in payload
	copy(body[4:], data)

	msg := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}
	// Kernel inserts the checksum for IPv6.
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

		pkt, err := parseICMPv6(buf[:n], src)
		if err != nil {
			continue
		}

		select {
		case c.recvBuf <- pkt:
		case <-c.closed:
			return
		default:
			log.Printf("icmpv6: recv buffer full, dropping packet")
		}
	}
}

// parseICMPv6 parses a raw ICMPv6 message. Returns a RawPacket preserving
// the source Zone (critical for link-local reply routing).
func parseICMPv6(raw []byte, src net.Addr) (*RawPacket, error) {
	msg, err := icmp.ParseMessage(58 /* ICMPv6 */, raw)
	if err != nil {
		return nil, err
	}

	var msgType byte
	var expectedID uint16
	switch msg.Type {
	case ipv6.ICMPTypeEchoRequest:
		msgType = ICMPv6TypeEchoRequest
		expectedID = ICMPRequestID
	case ipv6.ICMPTypeEchoReply:
		msgType = ICMPv6TypeEchoReply
		expectedID = ICMPReplyID
	default:
		return nil, errors.New("not echo")
	}

	body, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, errors.New("not echo body")
	}
	// Validate the ICMP identifier. The Linux kernel auto-replies to Echo
	// Requests using the same ID as the request (ICMPRequestID=0x5348).
	// Since sshoi-server sends replies with ICMPReplyID=0x5349, the client
	// filters out kernel echoes by rejecting replies with the wrong ID.
	if uint16(body.ID) != expectedID {
		return nil, errors.New("wrong identifier")
	}

	payload := make([]byte, len(body.Data))
	copy(payload, body.Data)

	// Preserve the full IPAddr including Zone so link-local replies work.
	var srcAddr *net.IPAddr
	switch a := src.(type) {
	case *net.IPAddr:
		srcAddr = &net.IPAddr{IP: a.IP, Zone: a.Zone}
	case *net.UDPAddr:
		srcAddr = &net.IPAddr{IP: a.IP, Zone: a.Zone}
	default:
		srcAddr = &net.IPAddr{IP: net.IPv6zero}
	}

	return &RawPacket{
		Src:  srcAddr,
		Type: msgType,
		Data: payload,
	}, nil
}
