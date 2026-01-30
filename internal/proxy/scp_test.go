package proxy

import (
	"testing"

	"sshmonkey/internal/askpass"
)

func TestBuildSCPEnvironment(t *testing.T) {
	// SCP uses the same BuildSSHEnvironment as SSH
	env, err := BuildSSHEnvironment("scphost.com", "scpuser", "/tmp/scp-vault.enc")
	if err != nil {
		t.Fatalf("BuildSSHEnvironment failed: %v", err)
	}

	envMap := envToMap(env)

	// Verify all required vars are set
	required := map[string]string{
		"SSH_ASKPASS_REQUIRE":  "force",
		askpass.EnvAskpassMode: "1",
		askpass.EnvHost:        "scphost.com",
		askpass.EnvUser:        "scpuser",
		askpass.EnvVaultPath:   "/tmp/scp-vault.enc",
	}

	for key, want := range required {
		got, ok := envMap[key]
		if !ok {
			t.Errorf("missing env var %s", key)
			continue
		}
		if got != want {
			t.Errorf("env %s = %q, want %q", key, got, want)
		}
	}

	if _, ok := envMap["SSH_ASKPASS"]; !ok {
		t.Error("missing SSH_ASKPASS env var")
	}
}

func TestSCPFailFastOnUnknownHost(t *testing.T) {
	// RunSCP should fail before spawning scp if host not in vault
	// We can't easily test this without a vault file, but we can verify
	// the error path by calling with a nonexistent vault path
	err := RunSCP([]string{"file.txt", "nobody@unknown.host:/tmp/"}, "/nonexistent/vault.enc")
	if err == nil {
		t.Fatal("expected error for unknown host / nonexistent vault")
	}
}
