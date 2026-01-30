package askpass

import (
	"os"
	"path/filepath"
	"testing"

	"sshmonkey/internal/vault"
)

func TestIsAskpassMode_Set(t *testing.T) {
	os.Setenv(EnvAskpassMode, "1")
	defer os.Unsetenv(EnvAskpassMode)

	if !IsAskpassMode() {
		t.Error("IsAskpassMode() = false, want true when env var set")
	}
}

func TestIsAskpassMode_Unset(t *testing.T) {
	os.Unsetenv(EnvAskpassMode)

	if IsAskpassMode() {
		t.Error("IsAskpassMode() = true, want false when env var unset")
	}
}

func TestIsAskpassMode_WrongValue(t *testing.T) {
	os.Setenv(EnvAskpassMode, "yes")
	defer os.Unsetenv(EnvAskpassMode)

	if IsAskpassMode() {
		t.Error("IsAskpassMode() = true, want false when env var is not '1'")
	}
}

// createTestVault creates a vault with a test entry and returns the vault path.
func createTestVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.enc")

	v, salt, err := vault.Load(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	v.Add(vault.Entry{
		Host:     "test-server.com",
		User:     "testuser",
		Password: "testpassword123",
	})

	if err := v.Save(vaultPath, salt); err != nil {
		t.Fatal(err)
	}

	return vaultPath
}

func TestRunAskpass_Success(t *testing.T) {
	vaultPath := createTestVault(t)

	os.Setenv(EnvHost, "test-server.com")
	os.Setenv(EnvUser, "testuser")
	os.Setenv(EnvVaultPath, vaultPath)
	defer func() {
		os.Unsetenv(EnvHost)
		os.Unsetenv(EnvUser)
		os.Unsetenv(EnvVaultPath)
	}()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := RunAskpass()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("RunAskpass failed: %v", err)
	}

	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if output != "testpassword123" {
		t.Errorf("output = %q, want %q", output, "testpassword123")
	}
}

func TestRunAskpass_MissingHost(t *testing.T) {
	os.Unsetenv(EnvHost)
	os.Setenv(EnvUser, "testuser")
	defer os.Unsetenv(EnvUser)

	err := RunAskpass()
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestRunAskpass_MissingUser(t *testing.T) {
	os.Setenv(EnvHost, "test-server.com")
	os.Unsetenv(EnvUser)
	defer os.Unsetenv(EnvHost)

	err := RunAskpass()
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestRunAskpass_UnknownHost(t *testing.T) {
	vaultPath := createTestVault(t)

	os.Setenv(EnvHost, "unknown-host.com")
	os.Setenv(EnvUser, "nobody")
	os.Setenv(EnvVaultPath, vaultPath)
	defer func() {
		os.Unsetenv(EnvHost)
		os.Unsetenv(EnvUser)
		os.Unsetenv(EnvVaultPath)
	}()

	err := RunAskpass()
	if err == nil {
		t.Fatal("expected error for unknown host")
	}
}

func TestRunAskpass_NoNewline(t *testing.T) {
	vaultPath := createTestVault(t)

	os.Setenv(EnvHost, "test-server.com")
	os.Setenv(EnvUser, "testuser")
	os.Setenv(EnvVaultPath, vaultPath)
	defer func() {
		os.Unsetenv(EnvHost)
		os.Unsetenv(EnvUser)
		os.Unsetenv(EnvVaultPath)
	}()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := RunAskpass()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("RunAskpass failed: %v", err)
	}

	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Must NOT end with newline
	if len(output) > 0 && output[len(output)-1] == '\n' {
		t.Error("output ends with newline, want no trailing newline")
	}
}
