package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SSHTarget represents the parsed destination from SSH arguments.
type SSHTarget struct {
	User string
	Host string
	Port int
}

// SCPTarget represents a parsed source or destination from SCP arguments.
type SCPTarget struct {
	User     string
	Host     string
	Port     int
	Path     string
	IsRemote bool
}

// SSH flags that consume the next argument as their value.
var sshFlagsWithValue = map[string]bool{
	"-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
	"-F": true, "-I": true, "-i": true, "-J": true, "-L": true,
	"-l": true, "-m": true, "-O": true, "-o": true, "-p": true,
	"-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
}

// SSH flags that stand alone (no value argument).
var sshStandaloneFlags = map[string]bool{
	"-4": true, "-6": true, "-A": true, "-a": true, "-C": true,
	"-f": true, "-G": true, "-g": true, "-K": true, "-k": true,
	"-M": true, "-N": true, "-n": true, "-q": true, "-s": true,
	"-T": true, "-t": true, "-V": true, "-v": true, "-X": true,
	"-x": true, "-Y": true, "-y": true,
}

// SCP flags that consume the next argument as their value.
var scpFlagsWithValue = map[string]bool{
	"-c": true, "-F": true, "-i": true, "-J": true,
	"-l": true, "-o": true, "-P": true, "-S": true,
}

// SCP flags that stand alone (no value argument).
var scpStandaloneFlags = map[string]bool{
	"-3": true, "-4": true, "-6": true, "-B": true, "-C": true,
	"-p": true, "-q": true, "-r": true, "-T": true, "-v": true,
	"-O": true, "-D": true,
}

// ParseSSHArgs extracts the SSH target (user, host, port) from ssh-style arguments.
// It returns the parsed target, the original args (for pass-through to real ssh), and any error.
func ParseSSHArgs(args []string) (*SSHTarget, []string, error) {
	if len(args) == 0 {
		return nil, nil, errors.New("no destination specified")
	}

	target := &SSHTarget{}
	destinationFound := false

	i := 0
	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") && !destinationFound {
			if sshFlagsWithValue[arg] {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("flag %s requires a value", arg)
				}
				value := args[i+1]

				switch arg {
				case "-l":
					target.User = value
				case "-p":
					port, err := strconv.Atoi(value)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid port: %s", value)
					}
					target.Port = port
				}

				i += 2
				continue
			}

			if sshStandaloneFlags[arg] {
				i++
				continue
			}

			// Unknown flag — treat as standalone and skip
			i++
			continue
		}

		if !destinationFound {
			// First non-flag argument is the destination
			destinationFound = true
			if idx := strings.Index(arg, "@"); idx >= 0 {
				target.User = arg[:idx]
				target.Host = arg[idx+1:]
			} else {
				target.Host = arg
			}
			i++
			// Everything after destination is remote command — stop parsing flags
			break
		}
	}

	if !destinationFound || target.Host == "" {
		return nil, nil, errors.New("no destination specified")
	}

	return target, args, nil
}

// ParseSCPArgs extracts remote targets from scp-style arguments.
// It returns all remote targets found, the original args (for pass-through), and any error.
func ParseSCPArgs(args []string) ([]SCPTarget, []string, error) {
	if len(args) == 0 {
		return nil, nil, errors.New("no arguments specified")
	}

	var targets []SCPTarget
	port := 0

	// First pass: extract flags
	i := 0
	var fileArgs []string

	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			if scpFlagsWithValue[arg] {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("flag %s requires a value", arg)
				}
				value := args[i+1]

				if arg == "-P" {
					p, err := strconv.Atoi(value)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid port: %s", value)
					}
					port = p
				}

				i += 2
				continue
			}

			if scpStandaloneFlags[arg] {
				i++
				continue
			}

			// Unknown flag — skip
			i++
			continue
		}

		fileArgs = append(fileArgs, arg)
		i++
	}

	// Second pass: classify file args as local or remote
	for _, arg := range fileArgs {
		t := parseSCPFileArg(arg)
		if t.IsRemote && port > 0 {
			t.Port = port
		}
		targets = append(targets, t)
	}

	return targets, args, nil
}

// parseSCPFileArg parses a single SCP file argument into an SCPTarget.
func parseSCPFileArg(arg string) SCPTarget {
	// Check for remote pattern: user@host:path or host:path
	colonIdx := strings.Index(arg, ":")
	if colonIdx < 0 {
		// No colon — local file
		return SCPTarget{Path: arg, IsRemote: false}
	}

	left := arg[:colonIdx]
	path := arg[colonIdx+1:]

	// Check if the part before colon looks like a remote spec
	if atIdx := strings.Index(left, "@"); atIdx >= 0 {
		return SCPTarget{
			User:     left[:atIdx],
			Host:     left[atIdx+1:],
			Path:     path,
			IsRemote: true,
		}
	}

	// host:path (no user)
	return SCPTarget{
		Host:     left,
		Path:     path,
		IsRemote: true,
	}
}
