package tunnel

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

var ErrDecryptFailed = errors.New("AEAD open failed: authentication tag mismatch")

const hkdfSalt = "sshoi-v1-key-derivation"

// Cipher wraps an XChaCha20-Poly1305 AEAD.
type Cipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
}

// NewCipherFromKey creates a Cipher from a raw 32-byte key.
func NewCipherFromKey(key []byte) (*Cipher, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// NewCipherFromPassphrase derives a 32-byte key via HKDF-SHA256 and calls
// NewCipherFromKey.
func NewCipherFromPassphrase(passphrase string) (*Cipher, error) {
	r := hkdf.New(sha256.New, []byte(passphrase), []byte(hkdfSalt), nil)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return NewCipherFromKey(key)
}

// Seal encrypts and authenticates plaintext.
// aad should be the raw HeaderLen bytes of the packet being sealed.
// Returns (nonce, ciphertext+tag, error).
func (c *Cipher) Seal(plaintext, aad []byte) (nonce [NonceLen]byte, ciphertext []byte, err error) {
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}
	ciphertext = c.aead.Seal(nil, nonce[:], plaintext, aad)
	return
}

// Open decrypts and authenticates ciphertext.
func (c *Cipher) Open(nonce [NonceLen]byte, ciphertext, aad []byte) ([]byte, error) {
	plain, err := c.aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}
