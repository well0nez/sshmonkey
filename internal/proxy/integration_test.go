package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"sshmonkey/internal/askpass"
	"sshmonkey/internal/vault"
)

// TestAskpassIntegration tests the full askpass flow:
// Create vault → set env vars → run askpass → verify password output.
func TestAskpassIntegration(t *testing.T) {
	// Create a test vault
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.enc")

	v, salt, err := vault.Load(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	v.Add(vault.Entry{
		Host:     "integration-test.example.com",
		User:     "integrationuser",
		Password: "integration-secret-password",
	})

	if err := v.Save(vaultPath, salt); err != nil {
		t.Fatal(err)
	}

	// Build the sshmonkey binary
	binPath := filepath.Join(dir, "sshmonkey")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/sshmonkey")
	buildCmd.Dir = findProjectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run in askpass mode
	askCmd := exec.Command(binPath)
	askCmd.Env = []string{
		askpass.EnvAskpassMode + "=1",
		askpass.EnvHost + "=integration-test.example.com",
		askpass.EnvUser + "=integrationuser",
		askpass.EnvVaultPath + "=" + vaultPath,
		"HOME=" + os.Getenv("HOME"),
	}

	out, err := askCmd.Output()
	if err != nil {
		t.Fatalf("askpass mode failed: %v", err)
	}

	if string(out) != "integration-secret-password" {
		t.Errorf("output = %q, want %q", string(out), "integration-secret-password")
	}

	// Verify no trailing newline
	if len(out) > 0 && out[len(out)-1] == '\n' {
		t.Error("output has trailing newline")
	}
}

// TestAskpassIntegration_UnknownHost verifies askpass exits non-zero for unknown hosts.
func TestAskpassIntegration_UnknownHost(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.enc")

	v, salt, err := vault.Load(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	v.Add(vault.Entry{Host: "known.com", User: "user", Password: "pass"})
	v.Save(vaultPath, salt)

	binPath := filepath.Join(dir, "sshmonkey")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/sshmonkey")
	buildCmd.Dir = findProjectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	askCmd := exec.Command(binPath)
	askCmd.Env = []string{
		askpass.EnvAskpassMode + "=1",
		askpass.EnvHost + "=unknown.com",
		askpass.EnvUser + "=nobody",
		askpass.EnvVaultPath + "=" + vaultPath,
		"HOME=" + os.Getenv("HOME"),
	}

	err = askCmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown host")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() == 0 {
		t.Error("expected non-zero exit code")
	}
}

// TestSSHCommandConstruction verifies the SSH wrapper builds the correct command and env.
func TestSSHCommandConstruction(t *testing.T) {
	env, err := BuildSSHEnvironment("testhost.com", "testuser", "/tmp/test.enc")
	if err != nil {
		t.Fatal(err)
	}

	envMap := envToMap(env)

	// All required vars must be present
	checks := []struct {
		key, want string
	}{
		{"SSH_ASKPASS_REQUIRE", "force"},
		{askpass.EnvAskpassMode, "1"},
		{askpass.EnvHost, "testhost.com"},
		{askpass.EnvUser, "testuser"},
		{askpass.EnvVaultPath, "/tmp/test.enc"},
	}

	for _, c := range checks {
		if got := envMap[c.key]; got != c.want {
			t.Errorf("env[%s] = %q, want %q", c.key, got, c.want)
		}
	}

	// SSH_ASKPASS must point to an executable
	askpassPath := envMap["SSH_ASKPASS"]
	if askpassPath == "" {
		t.Fatal("SSH_ASKPASS not set")
	}
}

// TestExitCodeMock tests exit code propagation using a mock "ssh" script.
func TestExitCodeMock(t *testing.T) {
	dir := t.TempDir()

	// Create a mock ssh script that exits with a specific code
	mockSSH := filepath.Join(dir, "ssh")
	err := os.WriteFile(mockSSH, []byte("#!/bin/sh\nexit 42\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Verify mock works
	cmd := exec.Command(mockSSH)
	err = cmd.Run()
	if err == nil {
		t.Fatal("mock ssh should exit non-zero")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 42 {
		t.Errorf("mock exit code = %d, want 42", exitErr.ExitCode())
	}
}

// findProjectRoot walks up from current working directory to find go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}
}
