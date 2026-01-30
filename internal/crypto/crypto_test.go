package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello sshmonkey vault")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret data")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF

	_, err = Decrypt(ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("integrity check")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = Decrypt(tampered, key)
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	machineID := []byte("test-machine-id")
	salt := []byte("test-salt-value-1234567890123456")

	key1 := DeriveKey(machineID, salt)
	key2 := DeriveKey(machineID, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveKey not deterministic: same inputs produced different keys")
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveKeyDifferentSalt(t *testing.T) {
	machineID := []byte("test-machine-id")
	salt1 := []byte("salt-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	salt2 := []byte("salt-bbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	key1 := DeriveKey(machineID, salt1)
	key2 := DeriveKey(machineID, salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts produced identical keys")
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same plaintext")

	ct1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	ct2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext produced identical ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	shortCiphertext := make([]byte, 5)

	_, err := Decrypt(shortCiphertext, key)
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than nonce")
	}
}
