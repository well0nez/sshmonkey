package askpass

import (
	"fmt"
	"os"

	"sshmonkey/internal/vault"
)

const (
	// EnvAskpassMode is set when sshmonkey is invoked as an SSH_ASKPASS helper.
	EnvAskpassMode = "SSHMONKEY_ASKPASS_MODE"
	// EnvHost is the target SSH host for password lookup.
	EnvHost = "SSHMONKEY_HOST"
	// EnvUser is the target SSH user for password lookup.
	EnvUser = "SSHMONKEY_USER"
	// EnvVaultPath overrides the default vault file path.
	EnvVaultPath = "SSHMONKEY_VAULT_PATH"
)

// IsAskpassMode returns true if the binary was invoked as an SSH_ASKPASS helper.
func IsAskpassMode() bool {
	return os.Getenv(EnvAskpassMode) == "1"
}

// RunAskpass executes the askpass mode: reads vault, looks up password, prints to stdout.
// This function should be called at the very start of main(), before cobra initialization.
// It prints the password to stdout WITHOUT a trailing newline (SSH reads it directly).
// Returns nil on success, error on failure. Caller should os.Exit(1) on error.
func RunAskpass() error {
	host := os.Getenv(EnvHost)
	user := os.Getenv(EnvUser)

	if host == "" {
		return fmt.Errorf("SSHMONKEY_HOST not set")
	}
	if user == "" {
		return fmt.Errorf("SSHMONKEY_USER not set")
	}

	vaultPath := os.Getenv(EnvVaultPath)
	if vaultPath == "" {
		vaultPath = vault.DefaultVaultPath()
	}

	v, _, err := vault.Load(vaultPath)
	if err != nil {
		return fmt.Errorf("load vault: %w", err)
	}

	entry, err := v.Lookup(host, user)
	if err != nil {
		return fmt.Errorf("lookup %s@%s: %w", user, host, err)
	}

	// Print password to stdout WITHOUT newline — SSH reads it directly
	fmt.Fprint(os.Stdout, entry.Password)
	return nil
}
