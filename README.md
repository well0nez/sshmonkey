# sshmonkey

**SSH password proxy** — connect to systems using stored passwords instead of SSH keys.

sshmonkey wraps the system `ssh` and `scp` binaries and automatically feeds passwords from a machine-bound encrypted vault. Built for systems that only support password authentication and for AI agent automation.

## Features

- **All SSH features** — port forwarding, ProxyJump, SOCKS proxy, agent forwarding, interactive shell, remote commands — everything works because sshmonkey wraps the real `ssh`/`scp`
- **Machine-bound encryption** — vault is encrypted with AES-256-GCM, key derived from `/etc/machine-id` via Argon2id. No master password needed. File is useless on another machine.
- **SSH_ASKPASS architecture** — uses the SSH_ASKPASS self-exec pattern (same approach as kitty and mutagen). No fragile prompt detection or PTY scanning.
- **Single binary** — one Go binary, zero runtime dependencies (besides OpenSSH)
- **AI agent friendly** — fully automated, no interactive prompts during SSH connections

## Requirements

- Linux (uses `/etc/machine-id` for key derivation)
- OpenSSH 8.4+ (for `SSH_ASKPASS_REQUIRE=force` support — released September 2020)

## Installation

### From release binary

Download the latest release from the [releases page](https://github.com/well0nez/sshmonkey/releases):

```bash
# Download and install
curl -L https://github.com/well0nez/sshmonkey/releases/latest/download/sshmonkey-linux-amd64 -o sshmonkey
chmod +x sshmonkey
sudo mv sshmonkey /usr/local/bin/
```

### From source

```bash
git clone https://github.com/well0nez/sshmonkey.git
cd sshmonkey
go build -o sshmonkey ./cmd/sshmonkey
sudo mv sshmonkey /usr/local/bin/
```

## Quick Start

```bash
# 1. Add a credential
sshmonkey vault add --host server.example.com --user admin
Password: ********

# 2. Connect via SSH — password is fed automatically
sshmonkey ssh admin@server.example.com

# 3. All SSH features work
sshmonkey ssh admin@server.example.com -L 8080:localhost:80   # port forwarding
sshmonkey ssh -J jumphost admin@target                         # ProxyJump
sshmonkey ssh admin@server.example.com -D 1080                 # SOCKS proxy
sshmonkey ssh admin@server.example.com 'ls -la /tmp'           # remote command

# 4. SCP works too
sshmonkey scp file.txt admin@server.example.com:/tmp/
sshmonkey scp admin@server.example.com:/var/log/syslog .
```

## Vault Management

```bash
# Add credential (prompts for password interactively)
sshmonkey vault add --host server.com --user deploy --port 2222 --name production

# List all stored credentials (passwords are never shown)
sshmonkey vault list
NAME         HOST          USER    PORT
production   server.com    deploy  2222

# Edit password
sshmonkey vault edit --host server.com --user deploy

# Remove credential
sshmonkey vault remove --host server.com --user deploy

# Use custom vault path
sshmonkey --vault-path /path/to/vault.enc vault list
```

### Wildcard Host Matching

Store a single credential for multiple hosts:

```bash
sshmonkey vault add --host "staging-*" --user deploy
# Matches: staging-web-01, staging-db-02, staging-cache-03, etc.
```

Lookup priority:
1. Exact match on `user@host`
2. Exact match on `host` (any user)
3. Glob pattern match (e.g., `staging-*`)

## How It Works

sshmonkey uses a dual-mode binary architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  sshmonkey ssh admin@server                                  │
│                                                              │
│  1. Parse args → extract user@host                           │
│  2. Load vault → decrypt with machine-bound key              │
│  3. Verify password exists for target                        │
│  4. Set environment:                                         │
│     SSH_ASKPASS=/proc/self/exe                                │
│     SSH_ASKPASS_REQUIRE=force                                 │
│     SSHMONKEY_ASKPASS_MODE=1                                  │
│     SSHMONKEY_HOST=server                                    │
│     SSHMONKEY_USER=admin                                     │
│  5. Start real `ssh` with PTY for interactive session        │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ssh needs password                                   │   │
│  │  → forks sshmonkey as SSH_ASKPASS subprocess           │   │
│  │  → sshmonkey detects askpass mode via env var          │   │
│  │  → reads vault, prints password to stdout              │   │
│  │  → ssh authenticates. Done.                            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Security Model

| Aspect | Implementation |
|--------|---------------|
| Encryption | AES-256-GCM (hardware-accelerated via AES-NI) |
| Key Derivation | Argon2id (time=3, memory=64MB, threads=4) |
| Machine Binding | Key derived from `/etc/machine-id` — vault is useless on another machine |
| Password Feeding | SSH_ASKPASS subprocess — password only exists in a short-lived stdout pipe |
| File Permissions | Vault file: `0600`, vault directory: `0700` |
| Atomic Writes | Temp file + `rename(2)` — no corruption on crash |
| Concurrent Access | `flock(2)` for write safety |
| Memory | Key material zeroed after use |

## For AI Agents

sshmonkey is designed for automated use. No interactive prompts occur during SSH/SCP connections:

```bash
# Agent workflow: vault is pre-populated, then any number of SSH operations
sshmonkey ssh deploy@web-01 'systemctl restart nginx'
sshmonkey ssh deploy@web-02 'systemctl restart nginx'
sshmonkey scp config.yaml deploy@web-01:/etc/app/
```

The only interactive step is `vault add` (initial password setup). After that, all operations are fully automated.

## Project Structure

```
sshmonkey/
├── cmd/sshmonkey/          # CLI entry point (cobra commands)
│   ├── main.go             # Askpass mode detection + cobra root
│   ├── vault.go            # vault add/list/edit/remove commands
│   ├── ssh.go              # ssh subcommand
│   └── scp.go              # scp subcommand
├── internal/
│   ├── askpass/             # SSH_ASKPASS self-exec mode
│   ├── crypto/              # AES-256-GCM + Argon2id
│   ├── parser/              # SSH/SCP argument parsing
│   ├── proxy/               # SSH/SCP wrappers with PTY
│   └── vault/               # Vault CRUD + file format
├── go.mod
└── Makefile
```

## License

MIT
