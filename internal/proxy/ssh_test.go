package proxy

import (
	"os"
	"strings"
	"testing"

	"sshmonkey/internal/askpass"
)

func TestBuildSSHEnvironment(t *testing.T) {
	env, err := BuildSSHEnvironment("example.com", "admin", "/tmp/test-vault.enc")
	if err != nil {
		t.Fatalf("BuildSSHEnvironment failed: %v", err)
	}

	required := map[string]string{
		"SSH_ASKPASS_REQUIRE":  "force",
		askpass.EnvAskpassMode: "1",
		askpass.EnvHost:        "example.com",
		askpass.EnvUser:        "admin",
		askpass.EnvVaultPath:   "/tmp/test-vault.enc",
	}

	envMap := envToMap(env)

	for key, wantVal := range required {
		gotVal, ok := envMap[key]
		if !ok {
			t.Errorf("missing env var %s", key)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("env %s = %q, want %q", key, gotVal, wantVal)
		}
	}

	// SSH_ASKPASS must be set to something (our executable path)
	if _, ok := envMap["SSH_ASKPASS"]; !ok {
		t.Error("missing SSH_ASKPASS env var")
	}
}

func TestSSHEnvironmentInheritsParent(t *testing.T) {
	os.Setenv("TEST_SSHMONKEY_INHERIT", "hello")
	defer os.Unsetenv("TEST_SSHMONKEY_INHERIT")

	env, err := BuildSSHEnvironment("host", "user", "/tmp/vault.enc")
	if err != nil {
		t.Fatal(err)
	}

	envMap := envToMap(env)
	if val, ok := envMap["TEST_SSHMONKEY_INHERIT"]; !ok || val != "hello" {
		t.Error("parent environment variable not inherited")
	}
}

func TestSSHEnvironmentHasDISPLAY(t *testing.T) {
	// Unset DISPLAY to test default
	oldDisplay := os.Getenv("DISPLAY")
	os.Unsetenv("DISPLAY")
	defer func() {
		if oldDisplay != "" {
			os.Setenv("DISPLAY", oldDisplay)
		}
	}()

	env, err := BuildSSHEnvironment("host", "user", "/tmp/vault.enc")
	if err != nil {
		t.Fatal(err)
	}

	envMap := envToMap(env)
	display, ok := envMap["DISPLAY"]
	if !ok {
		t.Fatal("DISPLAY not set")
	}
	if display != ":0" {
		t.Errorf("DISPLAY = %q, want %q", display, ":0")
	}
}

func TestSetEnv(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux"}

	// Replace existing
	env = setEnv(env, "FOO", "new")
	m := envToMap(env)
	if m["FOO"] != "new" {
		t.Errorf("FOO = %q, want %q", m["FOO"], "new")
	}

	// Add new
	env = setEnv(env, "NEW", "value")
	m = envToMap(env)
	if m["NEW"] != "value" {
		t.Errorf("NEW = %q, want %q", m["NEW"], "value")
	}
}

// envToMap converts an env slice to a map for easy lookup.
func envToMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
