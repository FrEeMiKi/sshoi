package tunnel

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeHeader(t *testing.T) {
	h := Header{
		SessionID:  0xABCD,
		Seq:        0xDEADBEEF,
		Ack:        0x12345678,
		Flags:      FlagDATA | FlagACK,
		PayloadLen: 512,
	}

	buf := make([]byte, HeaderLen)
	if err := EncodeHeader(buf, h); err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}

	// Verify magic.
	if string(buf[0:4]) != magic {
		t.Errorf("magic mismatch: %x", buf[0:4])
	}

	var h2 Header
	if err := DecodeHeader(buf, &h2); err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}

	if h != h2 {
		t.Errorf("header mismatch: got %+v, want %+v", h2, h)
	}
}

func TestDecodeHeader_BadMagic(t *testing.T) {
	buf := make([]byte, HeaderLen)
	buf[0] = 0xFF
	var h Header
	if err := DecodeHeader(buf, &h); err != ErrBadMagic {
		t.Errorf("expected ErrBadMagic, got %v", err)
	}
}

func TestDecodeHeader_TooShort(t *testing.T) {
	buf := make([]byte, 5)
	var h Header
	if err := DecodeHeader(buf, &h); err != ErrShortPacket {
		t.Errorf("expected ErrShortPacket, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	cipher, err := NewCipherFromPassphrase("test-passphrase")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	plaintext := []byte("hello sshoi tunnel")

	// Build a data packet manually as session.buildAndEnqueue does.
	hdr := Header{
		SessionID:  1,
		Seq:        42,
		Ack:        10,
		Flags:      FlagDATA | FlagACK,
		PayloadLen: uint16(len(plaintext)),
	}

	aadBuf := make([]byte, HeaderLen)
	if err := EncodeHeader(aadBuf, hdr); err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}

	nonce, ciphertext, err := cipher.Seal(plaintext, aadBuf)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wire, err := EncodePlaintext(hdr, nonce, ciphertext)
	if err != nil {
		t.Fatalf("EncodePlaintext: %v", err)
	}

	// Decode outer.
	h2, nonce2, ct2, err := DecodeOuter(wire)
	if err != nil {
		t.Fatalf("DecodeOuter: %v", err)
	}

	if h2 != hdr {
		t.Errorf("header mismatch: %+v vs %+v", h2, hdr)
	}
	if nonce != nonce2 {
		t.Errorf("nonce mismatch")
	}

	// Decrypt.
	aad2 := wire[:HeaderLen]
	plain2, err := cipher.Open(nonce2, ct2, aad2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plain2, plaintext) {
		t.Errorf("plaintext mismatch: got %q want %q", plain2, plaintext)
	}
}

func TestDecodeOuter_TooShort(t *testing.T) {
	_, _, _, err := DecodeOuter(make([]byte, 10))
	if err != ErrShortPacket {
		t.Errorf("expected ErrShortPacket, got %v", err)
	}
}
