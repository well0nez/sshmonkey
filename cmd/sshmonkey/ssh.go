package main

import (
	"fmt"
	"os"

	"sshmonkey/internal/proxy"

	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:                "ssh [ssh-args...]",
	Short:              "Connect via SSH using stored password",
	Long:               "Wraps system ssh and automatically feeds the password from the encrypted vault via SSH_ASKPASS.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: sshmonkey ssh [user@]host [ssh-options...]")
		}

		vp := getVaultPath()
		if err := proxy.RunSSH(args, vp); err != nil {
			fmt.Fprintf(os.Stderr, "sshmonkey ssh: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)
}
