package main

import (
	"fmt"
	"os"

	"sshmonkey/internal/proxy"

	"github.com/spf13/cobra"
)

var scpCmd = &cobra.Command{
	Use:                "scp [scp-args...]",
	Short:              "Transfer files via SCP using stored password",
	Long:               "Wraps system scp and automatically feeds the password from the encrypted vault via SSH_ASKPASS.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: sshmonkey scp [options] source... target")
		}

		vp := getVaultPath()
		if err := proxy.RunSCP(args, vp); err != nil {
			fmt.Fprintf(os.Stderr, "sshmonkey scp: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scpCmd)
}
