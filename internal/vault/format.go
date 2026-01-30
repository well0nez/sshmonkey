package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	MagicBytes    = "SSHM"
	FormatVersion = 1
	headerSize    = 4 + 2 + 32 // magic(4) + version(2) + salt(32)
)

// WriteVaultFile atomically writes a vault file with the binary format:
// magic(4B) || version(2B big-endian) || salt(32B) || encrypted payload.
func WriteVaultFile(path string, salt []byte, encrypted []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	header := make([]byte, headerSize)
	copy(header[0:4], MagicBytes)
	binary.BigEndian.PutUint16(header[4:6], FormatVersion)
	copy(header[6:38], salt)

	data := append(header, encrypted...)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp vault file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("atomic rename vault file: %w", err)
	}

	return nil
}

// ReadVaultFile reads and parses a vault file, returning the salt and encrypted payload.
func ReadVaultFile(path string) (salt []byte, encrypted []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read vault file: %w", err)
	}

	if len(data) < headerSize {
		return nil, nil, errors.New("vault file too short")
	}

	magic := string(data[0:4])
	if magic != MagicBytes {
		return nil, nil, fmt.Errorf("invalid magic bytes: expected %q, got %q", MagicBytes, magic)
	}

	version := binary.BigEndian.Uint16(data[4:6])
	if version != FormatVersion {
		return nil, nil, fmt.Errorf("unsupported vault format version: %d", version)
	}

	salt = make([]byte, 32)
	copy(salt, data[6:38])

	encrypted = make([]byte, len(data)-headerSize)
	copy(encrypted, data[headerSize:])

	return salt, encrypted, nil
}
