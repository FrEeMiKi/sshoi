// Package tunnel implements the sshoi wire protocol over ICMPv6.
package tunnel

import (
	"encoding/binary"
	"errors"
)

// Wire format (all multi-byte fields big-endian):
//
//	Offset  Len   Field
//	0       4     MAGIC        = [0x53,0x53,0x48,0x49] ("SSHI")
//	4       2     SESSION_ID   uint16
//	6       4     SEQ          uint32
//	10      4     ACK          uint32
//	14      1     FLAGS        bitmask
//	15      2     PAYLOAD_LEN  uint16  (plaintext bytes; excl. nonce/tag)
//	17      24    NONCE        XChaCha20 nonce
//	41      N     ENCRYPTED_DATA
//	41+N    16    POLY1305 TAG
const (
	magic        = "\x53\x53\x48\x49" // "SSHI"
	MagicLen     = 4
	HeaderLen    = 17 // magic+session+seq+ack+flags+payloadlen
	NonceLen     = 24
	TagLen       = 16
	OverheadLen  = HeaderLen + NonceLen + TagLen // 57 bytes
	MaxPayload   = 1024
	MaxPacketLen = OverheadLen + MaxPayload

	FlagSYN  byte = 0x01
	FlagFIN  byte = 0x02
	FlagACK  byte = 0x04
	FlagDATA byte = 0x08
	FlagKA   byte = 0x10
)

var (
	ErrShortPacket   = errors.New("packet too short")
	ErrBadMagic      = errors.New("bad magic bytes")
	ErrPayloadTooBig = errors.New("payload exceeds MaxPayload")
)

// Header is the decoded, unencrypted header of a tunnel packet.
type Header struct {
	SessionID  uint16
	Seq        uint32
	Ack        uint32
	Flags      byte
	PayloadLen uint16
}

// Packet is a fully decoded tunnel packet including plaintext payload.
type Packet struct {
	Header
	Nonce   [NonceLen]byte
	Payload []byte
}

// EncodeHeader serialises the header fields into dst[0:HeaderLen].
func EncodeHeader(dst []byte, h Header) error {
	if len(dst) < HeaderLen {
		return ErrShortPacket
	}
	copy(dst[0:4], magic)
	binary.BigEndian.PutUint16(dst[4:6], h.SessionID)
	binary.BigEndian.PutUint32(dst[6:10], h.Seq)
	binary.BigEndian.PutUint32(dst[10:14], h.Ack)
	dst[14] = h.Flags
	binary.BigEndian.PutUint16(dst[15:17], h.PayloadLen)
	return nil
}

// DecodeHeader parses src[0:HeaderLen] into h.
func DecodeHeader(src []byte, h *Header) error {
	if len(src) < HeaderLen {
		return ErrShortPacket
	}
	if string(src[0:4]) != magic {
		return ErrBadMagic
	}
	h.SessionID = binary.BigEndian.Uint16(src[4:6])
	h.Seq = binary.BigEndian.Uint32(src[6:10])
	h.Ack = binary.BigEndian.Uint32(src[10:14])
	h.Flags = src[14]
	h.PayloadLen = binary.BigEndian.Uint16(src[15:17])
	return nil
}

// EncodePlaintext assembles the full ICMPv6 data field from an already-encrypted
// ciphertext blob (ciphertext already includes the 16-byte Poly1305 tag appended
// by AEAD.Seal).
func EncodePlaintext(h Header, nonce [NonceLen]byte, ciphertext []byte) ([]byte, error) {
	if int(h.PayloadLen) > MaxPayload {
		return nil, ErrPayloadTooBig
	}
	total := HeaderLen + NonceLen + len(ciphertext)
	out := make([]byte, total)
	if err := EncodeHeader(out, h); err != nil {
		return nil, err
	}
	copy(out[HeaderLen:HeaderLen+NonceLen], nonce[:])
	copy(out[HeaderLen+NonceLen:], ciphertext)
	return out, nil
}

// DecodeOuter extracts header, nonce, and raw ciphertext+tag from a received
// ICMPv6 data field without performing decryption.
func DecodeOuter(raw []byte) (h Header, nonce [NonceLen]byte, ciphertext []byte, err error) {
	if len(raw) < OverheadLen {
		err = ErrShortPacket
		return
	}
	if err = DecodeHeader(raw, &h); err != nil {
		return
	}
	copy(nonce[:], raw[HeaderLen:HeaderLen+NonceLen])
	ciphertext = raw[HeaderLen+NonceLen:]
	// Sanity: ciphertext must be at least TagLen bytes.
	if len(ciphertext) < TagLen {
		err = ErrShortPacket
	}
	return
}
