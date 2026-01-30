package parser

import (
	"testing"
)

func TestParseSSHArgs_UserAtHost(t *testing.T) {
	target, args, err := ParseSSHArgs([]string{"user@host"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "user" {
		t.Errorf("User = %q, want %q", target.User, "user")
	}
	if target.Host != "host" {
		t.Errorf("Host = %q, want %q", target.Host, "host")
	}
	if target.Port != 0 {
		t.Errorf("Port = %d, want 0", target.Port)
	}
	if len(args) != 1 {
		t.Errorf("args len = %d, want 1", len(args))
	}
}

func TestParseSSHArgs_SeparateUser(t *testing.T) {
	target, _, err := ParseSSHArgs([]string{"-l", "admin", "host"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "admin" {
		t.Errorf("User = %q, want %q", target.User, "admin")
	}
	if target.Host != "host" {
		t.Errorf("Host = %q, want %q", target.Host, "host")
	}
}

func TestParseSSHArgs_CustomPort(t *testing.T) {
	target, _, err := ParseSSHArgs([]string{"-p", "2222", "user@host"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Port != 2222 {
		t.Errorf("Port = %d, want 2222", target.Port)
	}
	if target.User != "user" {
		t.Errorf("User = %q, want %q", target.User, "user")
	}
	if target.Host != "host" {
		t.Errorf("Host = %q, want %q", target.Host, "host")
	}
}

func TestParseSSHArgs_WithCommand(t *testing.T) {
	target, args, err := ParseSSHArgs([]string{"user@host", "ls", "-la"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "user" || target.Host != "host" {
		t.Errorf("target = %+v, want user@host", target)
	}
	// Original args preserved for pass-through
	if len(args) != 3 {
		t.Errorf("args len = %d, want 3", len(args))
	}
}

func TestParseSSHArgs_WithForwarding(t *testing.T) {
	target, args, err := ParseSSHArgs([]string{"-L", "8080:localhost:80", "user@host"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "user" || target.Host != "host" {
		t.Errorf("target = %+v, want user@host", target)
	}
	if len(args) != 3 {
		t.Errorf("args len = %d, want 3 (pass-through)", len(args))
	}
}

func TestParseSSHArgs_WithJump(t *testing.T) {
	target, _, err := ParseSSHArgs([]string{"-J", "jump", "user@target"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Host != "target" {
		t.Errorf("Host = %q, want %q (should be final destination, not jump host)", target.Host, "target")
	}
	if target.User != "user" {
		t.Errorf("User = %q, want %q", target.User, "user")
	}
}

func TestParseSSHArgs_NoHost(t *testing.T) {
	_, _, err := ParseSSHArgs([]string{})
	if err == nil {
		t.Fatal("expected error for empty args")
	}
}

func TestParseSSHArgs_ComplexArgs(t *testing.T) {
	target, _, err := ParseSSHArgs([]string{
		"-p", "2222", "-L", "8080:localhost:80", "-A", "admin@server", "ls",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "admin" {
		t.Errorf("User = %q, want %q", target.User, "admin")
	}
	if target.Host != "server" {
		t.Errorf("Host = %q, want %q", target.Host, "server")
	}
	if target.Port != 2222 {
		t.Errorf("Port = %d, want 2222", target.Port)
	}
}

func TestParseSSHArgs_MultipleSingleFlags(t *testing.T) {
	target, _, err := ParseSSHArgs([]string{"-v", "-N", "user@host"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.User != "user" || target.Host != "host" {
		t.Errorf("target = %+v, want user@host", target)
	}
}

func TestParseSCPArgs_Upload(t *testing.T) {
	targets, args, err := ParseSCPArgs([]string{"file.txt", "user@host:/tmp/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets len = %d, want 2", len(targets))
	}
	// First target is local
	if targets[0].IsRemote {
		t.Error("first target should be local")
	}
	// Second target is remote
	if !targets[1].IsRemote {
		t.Fatal("second target should be remote")
	}
	if targets[1].User != "user" {
		t.Errorf("User = %q, want %q", targets[1].User, "user")
	}
	if targets[1].Host != "host" {
		t.Errorf("Host = %q, want %q", targets[1].Host, "host")
	}
	if targets[1].Path != "/tmp/" {
		t.Errorf("Path = %q, want %q", targets[1].Path, "/tmp/")
	}
	if len(args) != 2 {
		t.Errorf("args len = %d, want 2", len(args))
	}
}

func TestParseSCPArgs_Download(t *testing.T) {
	targets, _, err := ParseSCPArgs([]string{"user@host:/tmp/file.txt", "."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, tgt := range targets {
		if tgt.IsRemote {
			found = true
			if tgt.Path != "/tmp/file.txt" {
				t.Errorf("Path = %q, want %q", tgt.Path, "/tmp/file.txt")
			}
			if tgt.User != "user" || tgt.Host != "host" {
				t.Errorf("target = %+v, want user@host", tgt)
			}
		}
	}
	if !found {
		t.Fatal("no remote target found")
	}
}

func TestParseSCPArgs_CustomPort(t *testing.T) {
	targets, _, err := ParseSCPArgs([]string{"-P", "2222", "file.txt", "user@host:/tmp/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tgt := range targets {
		if tgt.IsRemote {
			if tgt.Port != 2222 {
				t.Errorf("Port = %d, want 2222", tgt.Port)
			}
		}
	}
}

func TestParseSCPArgs_NoRemote(t *testing.T) {
	targets, _, err := ParseSCPArgs([]string{"file1.txt", "file2.txt"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tgt := range targets {
		if tgt.IsRemote {
			t.Error("expected no remote targets")
		}
	}
}
