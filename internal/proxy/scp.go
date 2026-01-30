package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"sshmonkey/internal/parser"
	"sshmonkey/internal/vault"
)

// RunSCP executes an SCP transfer with password from the vault via SSH_ASKPASS.
// SCP is non-interactive, so no PTY is needed. Instead, we use setsid to detach
// from the controlling terminal, which forces SSH (used internally by SCP) to
// use SSH_ASKPASS for authentication.
func RunSCP(args []string, vaultPath string) error {
	// 1. Parse args to extract remote target(s)
	targets, _, err := parser.ParseSCPArgs(args)
	if err != nil {
		return fmt.Errorf("parse SCP args: %w", err)
	}

	// Find first remote target for vault lookup
	var remoteHost, remoteUser string
	for _, t := range targets {
		if t.IsRemote {
			remoteHost = t.Host
			remoteUser = t.User
			break
		}
	}

	if remoteHost == "" {
		return fmt.Errorf("no remote target found in SCP arguments")
	}

	// 2. Verify target exists in vault (fail fast)
	v, _, err := vault.Load(vaultPath)
	if err != nil {
		return fmt.Errorf("load vault: %w", err)
	}

	_, err = v.Lookup(remoteHost, remoteUser)
	if err != nil {
		return fmt.Errorf("no password found for %s@%s: %w", remoteUser, remoteHost, err)
	}

	// 3. Build environment (same as SSH wrapper)
	env, err := BuildSSHEnvironment(remoteHost, remoteUser, vaultPath)
	if err != nil {
		return fmt.Errorf("build environment: %w", err)
	}

	// 4. Create SCP command with setsid (detach from controlling terminal)
	// This ensures SSH_ASKPASS is used since there's no TTY
	cmd := exec.Command("scp", args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	// 5. Run and wait
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("SCP failed: %w", err)
	}

	return nil
}
