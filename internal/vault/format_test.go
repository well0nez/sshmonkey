package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadVaultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vault")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	encrypted := []byte("encrypted-payload-data")

	if err := WriteVaultFile(path, salt, encrypted); err != nil {
		t.Fatalf("WriteVaultFile failed: %v", err)
	}

	gotSalt, gotEncrypted, err := ReadVaultFile(path)
	if err != nil {
		t.Fatalf("ReadVaultFile failed: %v", err)
	}

	if !bytes.Equal(salt, gotSalt) {
		t.Fatalf("salt mismatch: got %x, want %x", gotSalt, salt)
	}
	if !bytes.Equal(encrypted, gotEncrypted) {
		t.Fatalf("encrypted mismatch: got %x, want %x", gotEncrypted, encrypted)
	}
}

func TestVaultFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perms.vault")

	salt := make([]byte, 32)
	encrypted := []byte("data")

	if err := WriteVaultFile(path, salt, encrypted); err != nil {
		t.Fatalf("WriteVaultFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected permissions 0600, got %04o", perm)
	}
}

func TestInvalidMagicBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.vault")

	data := make([]byte, headerSize)
	copy(data[0:4], "BAAD")

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, _, err := ReadVaultFile(path)
	if err == nil {
		t.Fatal("expected error for invalid magic bytes")
	}

	expected := `invalid magic bytes: expected "SSHM", got "BAAD"`
	if err.Error() != expected {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.vault")

	salt := make([]byte, 32)
	encrypted := []byte("atomic-test")

	if err := WriteVaultFile(path, salt, encrypted); err != nil {
		t.Fatalf("WriteVaultFile failed: %v", err)
	}

	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp file still exists after atomic write: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("final vault file does not exist: %v", err)
	}
}

func TestReadNonexistent(t *testing.T) {
	_, _, err := ReadVaultFile("/nonexistent/path/vault.dat")
	if err == nil {
		t.Fatal("expected error reading non-existent file")
	}
}
