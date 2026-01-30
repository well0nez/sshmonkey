package proxy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"

	"sshmonkey/internal/askpass"
	"sshmonkey/internal/parser"
	"sshmonkey/internal/vault"
)

// RunSSH executes an SSH connection with password from the vault via SSH_ASKPASS.
// It creates a PTY for the interactive session and sets up sshmonkey as the SSH_ASKPASS helper.
func RunSSH(args []string, vaultPath string) error {
	// 1. Parse args to extract target
	target, _, err := parser.ParseSSHArgs(args)
	if err != nil {
		return fmt.Errorf("parse SSH args: %w", err)
	}

	// 2. Verify target exists in vault (fail fast)
	v, _, err := vault.Load(vaultPath)
	if err != nil {
		return fmt.Errorf("load vault: %w", err)
	}

	_, err = v.Lookup(target.Host, target.User)
	if err != nil {
		return fmt.Errorf("no password found for %s@%s: %w", target.User, target.Host, err)
	}

	// 3. Build environment for SSH with SSH_ASKPASS pointing to ourselves
	env, err := BuildSSHEnvironment(target.Host, target.User, vaultPath)
	if err != nil {
		return fmt.Errorf("build environment: %w", err)
	}

	// 4. Create SSH command
	cmd := exec.Command("ssh", args...)
	cmd.Env = env

	// 5. Start with PTY for interactive session
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start SSH with PTY: %w", err)
	}
	defer ptmx.Close()

	// 6. Handle SIGWINCH for terminal resize
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	sigCh <- syscall.SIGWINCH // Initial resize

	// 7. Set raw mode on stdin for interactive session
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			defer term.Restore(int(os.Stdin.Fd()), oldState)
		}
	}

	// 8. Bidirectional I/O copy
	// User input → PTY
	go func() {
		io.Copy(ptmx, os.Stdin)
	}()

	// PTY output → User (handles EIO on child exit as EOF)
	io.Copy(os.Stdout, ptmx)

	// 9. Wait for SSH to exit
	err = cmd.Wait()

	// 10. Prevent GC from closing PTY prematurely
	runtime.KeepAlive(ptmx)

	// 11. Clean up signal handler
	signal.Stop(sigCh)
	close(sigCh)

	// 12. Propagate SSH exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("SSH exited with error: %w", err)
	}

	return nil
}

// BuildSSHEnvironment creates the environment variables for the SSH process.
// It inherits the parent environment and adds SSH_ASKPASS configuration.
func BuildSSHEnvironment(host, user, vaultPath string) ([]string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}

	// Start with parent environment
	env := os.Environ()

	// Add SSH_ASKPASS configuration
	env = setEnv(env, "SSH_ASKPASS", selfPath)
	env = setEnv(env, "SSH_ASKPASS_REQUIRE", "force")
	env = setEnv(env, askpass.EnvAskpassMode, "1")
	env = setEnv(env, askpass.EnvHost, host)
	env = setEnv(env, askpass.EnvUser, user)
	env = setEnv(env, askpass.EnvVaultPath, vaultPath)

	// SSH_ASKPASS requires DISPLAY to be set (even if unused)
	if os.Getenv("DISPLAY") == "" {
		env = setEnv(env, "DISPLAY", ":0")
	}

	return env, nil
}

// setEnv sets or replaces an environment variable in a slice.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
