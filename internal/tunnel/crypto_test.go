package tunnel

import (
	"bytes"
	"testing"
)

func TestCipherSealOpen(t *testing.T) {
	c, err := NewCipherFromPassphrase("my-secret")
	if err != nil {
		t.Fatalf("NewCipherFromPassphrase: %v", err)
	}

	plaintext := []byte("tunnel test payload")
	aad := []byte("header-bytes")

	nonce, ciphertext, err := c.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	plain, err := c.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(plain, plaintext) {
		t.Errorf("plaintext mismatch: got %q want %q", plain, plaintext)
	}
}

func TestCipherOpen_TamperedAAD(t *testing.T) {
	c, err := NewCipherFromPassphrase("my-secret")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("payload")
	aad := []byte("header")

	nonce, ciphertext, err := c.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with AAD.
	tampered := []byte("TAMPERED")
	_, err = c.Open(nonce, ciphertext, tampered)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed on tampered AAD, got %v", err)
	}
}

func TestCipherOpen_TamperedCiphertext(t *testing.T) {
	c, err := NewCipherFromPassphrase("my-secret")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("payload")
	aad := []byte("header")

	nonce, ciphertext, err := c.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[0] ^= 0xFF
	_, err = c.Open(nonce, ciphertext, aad)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed on tampered ciphertext, got %v", err)
	}
}

func TestCipherFromKey_WrongLength(t *testing.T) {
	_, err := NewCipherFromKey([]byte("short"))
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestDifferentPassphrasesProduceDifferentKeys(t *testing.T) {
	c1, _ := NewCipherFromPassphrase("passA")
	c2, _ := NewCipherFromPassphrase("passB")

	plaintext := []byte("data")
	aad := []byte("aad")

	nonce, ct, err := c1.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// c2 should fail to open c1's ciphertext.
	_, err = c2.Open(nonce, ct, aad)
	if err != ErrDecryptFailed {
		t.Error("different passphrases should not interoperate")
	}
}
