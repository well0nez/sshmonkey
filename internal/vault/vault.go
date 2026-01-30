package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"sshmonkey/internal/crypto"
)

// Entry represents a single stored credential.
type Entry struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// Vault holds the in-memory vault data.
type Vault struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// DefaultVaultPath returns the default vault file path (~/.sshmonkey/vault.enc).
func DefaultVaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".sshmonkey", "vault.enc")
	}
	return filepath.Join(home, ".sshmonkey", "vault.enc")
}

// Load reads and decrypts the vault file. Returns an empty vault if the file doesn't exist.
func Load(path string) (*Vault, []byte, error) {
	v := &Vault{Version: 1}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		// No vault yet — return empty vault with fresh salt
		salt, err := crypto.GenerateSalt()
		if err != nil {
			return nil, nil, fmt.Errorf("generate salt: %w", err)
		}
		return v, salt, nil
	}

	salt, encrypted, err := ReadVaultFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read vault: %w", err)
	}

	machineID, err := crypto.ReadMachineID()
	if err != nil {
		return nil, nil, fmt.Errorf("read machine ID: %w", err)
	}

	key := crypto.DeriveKey(machineID, salt)
	defer clearBytes(key)

	plaintext, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt vault: %w", err)
	}

	if err := json.Unmarshal(plaintext, v); err != nil {
		return nil, nil, fmt.Errorf("parse vault JSON: %w", err)
	}

	return v, salt, nil
}

// Save encrypts and writes the vault to disk atomically.
func (v *Vault) Save(path string, salt []byte) error {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}

	machineID, err := crypto.ReadMachineID()
	if err != nil {
		return fmt.Errorf("read machine ID: %w", err)
	}

	key := crypto.DeriveKey(machineID, salt)
	defer clearBytes(key)

	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	// Use flock for concurrent write safety
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}

	lockPath := path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("create lock file: %w", err)
	}
	defer lockFile.Close()
	defer os.Remove(lockPath)

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	return WriteVaultFile(path, salt, encrypted)
}

// Add adds a new entry to the vault. Returns error if duplicate host+user exists.
func (v *Vault) Add(entry Entry) error {
	for _, e := range v.Entries {
		if e.Host == entry.Host && e.User == entry.User {
			return fmt.Errorf("entry for %s@%s already exists", entry.User, entry.Host)
		}
	}
	v.Entries = append(v.Entries, entry)
	return nil
}

// Remove removes an entry by host and user. Returns error if not found.
func (v *Vault) Remove(host, user string) error {
	for i, e := range v.Entries {
		if e.Host == host && e.User == user {
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no entry found for %s@%s", user, host)
}

// Edit updates the password for an existing entry. Returns error if not found.
func (v *Vault) Edit(host, user, newPassword string) error {
	for i, e := range v.Entries {
		if e.Host == host && e.User == user {
			v.Entries[i].Password = newPassword
			return nil
		}
	}
	return fmt.Errorf("no entry found for %s@%s", user, host)
}

// List returns all entries (caller should not expose passwords).
func (v *Vault) List() []Entry {
	return v.Entries
}

// Lookup finds a matching entry with priority:
// 1. Exact match on host + user
// 2. Exact match on host (any user in entry)
// 3. Glob pattern match on host
func (v *Vault) Lookup(host, user string) (*Entry, error) {
	// Priority 1: Exact host + user match
	for i, e := range v.Entries {
		if e.Host == host && e.User == user {
			return &v.Entries[i], nil
		}
	}

	// Priority 2: Exact host match (any user)
	if user != "" {
		for i, e := range v.Entries {
			if e.Host == host {
				return &v.Entries[i], nil
			}
		}
	}

	// Priority 3: Glob pattern match on host
	for i, e := range v.Entries {
		if strings.Contains(e.Host, "*") || strings.Contains(e.Host, "?") {
			matched, err := filepath.Match(e.Host, host)
			if err == nil && matched {
				if user == "" || e.User == user {
					return &v.Entries[i], nil
				}
				// Glob host match, different user — still return as fallback
				return &v.Entries[i], nil
			}
		}
	}

	return nil, fmt.Errorf("no entry found for %s@%s", user, host)
}

// EnsureVaultDir creates the vault directory with 0700 permissions if it doesn't exist.
func EnsureVaultDir() error {
	path := DefaultVaultPath()
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0700)
}

// clearBytes zeros a byte slice to remove sensitive data from memory.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
