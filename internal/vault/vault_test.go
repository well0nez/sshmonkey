package vault

import (
	"os"
	"path/filepath"
	"testing"

	"sshmonkey/internal/crypto"
)

// testSetup creates a temp vault with a test key for testing.
func testSetup(t *testing.T) (*Vault, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := &Vault{Version: 1}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}

	return v, salt, path
}

func TestAddAndList(t *testing.T) {
	v, _, _ := testSetup(t)

	entry := Entry{Name: "test", Host: "example.com", User: "admin", Password: "secret"}
	if err := v.Add(entry); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	list := v.List()
	if len(list) != 1 {
		t.Fatalf("List len = %d, want 1", len(list))
	}
	if list[0].Host != "example.com" || list[0].User != "admin" {
		t.Errorf("entry = %+v, want example.com/admin", list[0])
	}
}

func TestAddDuplicate(t *testing.T) {
	v, _, _ := testSetup(t)

	entry := Entry{Host: "example.com", User: "admin", Password: "secret"}
	if err := v.Add(entry); err != nil {
		t.Fatal(err)
	}

	err := v.Add(entry)
	if err == nil {
		t.Fatal("expected error for duplicate entry")
	}
}

func TestRemove(t *testing.T) {
	v, _, _ := testSetup(t)

	v.Add(Entry{Host: "example.com", User: "admin", Password: "secret"})
	v.Add(Entry{Host: "other.com", User: "root", Password: "pass"})

	if err := v.Remove("example.com", "admin"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	list := v.List()
	if len(list) != 1 {
		t.Fatalf("List len = %d, want 1 after remove", len(list))
	}
	if list[0].Host != "other.com" {
		t.Errorf("remaining entry = %+v, want other.com", list[0])
	}
}

func TestEdit(t *testing.T) {
	v, salt, path := testSetup(t)

	v.Add(Entry{Host: "example.com", User: "admin", Password: "old"})
	v.Save(path, salt)

	if err := v.Edit("example.com", "admin", "new"); err != nil {
		t.Fatalf("Edit failed: %v", err)
	}

	entry, err := v.Lookup("example.com", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Password != "new" {
		t.Errorf("Password = %q, want %q", entry.Password, "new")
	}
}

func TestLookupExactMatch(t *testing.T) {
	v, _, _ := testSetup(t)

	v.Add(Entry{Host: "server.com", User: "admin", Password: "p1"})
	v.Add(Entry{Host: "server.com", User: "root", Password: "p2"})

	entry, err := v.Lookup("server.com", "root")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Password != "p2" {
		t.Errorf("Password = %q, want %q (exact user match)", entry.Password, "p2")
	}
}

func TestLookupHostOnly(t *testing.T) {
	v, _, _ := testSetup(t)

	v.Add(Entry{Host: "server.com", User: "deploy", Password: "p1"})

	entry, err := v.Lookup("server.com", "other")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Password != "p1" {
		t.Errorf("Password = %q, want %q (host-only fallback)", entry.Password, "p1")
	}
}

func TestLookupGlob(t *testing.T) {
	v, _, _ := testSetup(t)

	v.Add(Entry{Host: "staging-*", User: "deploy", Password: "staging-pass"})

	entry, err := v.Lookup("staging-web-01", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Password != "staging-pass" {
		t.Errorf("Password = %q, want %q (glob match)", entry.Password, "staging-pass")
	}
}

func TestLookupPriority(t *testing.T) {
	v, _, _ := testSetup(t)

	v.Add(Entry{Host: "staging-*", User: "deploy", Password: "glob"})
	v.Add(Entry{Host: "staging-web-01", User: "deploy", Password: "exact"})

	entry, err := v.Lookup("staging-web-01", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Password != "exact" {
		t.Errorf("Password = %q, want %q (exact should win over glob)", entry.Password, "exact")
	}
}

func TestLookupNotFound(t *testing.T) {
	v, _, _ := testSetup(t)

	_, err := v.Lookup("unknown.com", "nobody")
	if err == nil {
		t.Fatal("expected error for unknown host")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	v, salt, path := testSetup(t)

	v.Add(Entry{Name: "prod", Host: "prod.example.com", Port: 22, User: "deploy", Password: "s3cret"})
	v.Add(Entry{Name: "staging", Host: "staging-*", User: "admin", Password: "staging123"})

	if err := v.Save(path, salt); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("vault file not found: %v", err)
	}

	loaded, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.Entries) != 2 {
		t.Fatalf("loaded entries = %d, want 2", len(loaded.Entries))
	}

	if loaded.Entries[0].Password != "s3cret" {
		t.Errorf("entry 0 password = %q, want %q", loaded.Entries[0].Password, "s3cret")
	}
	if loaded.Entries[1].Host != "staging-*" {
		t.Errorf("entry 1 host = %q, want %q", loaded.Entries[1].Host, "staging-*")
	}
}
