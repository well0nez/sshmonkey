package main

import (
	"fmt"
	"os"

	"sshmonkey/internal/askpass"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "sshmonkey",
	Short: "SSH password proxy — connect using stored passwords",
	Long:  "sshmonkey wraps system ssh/scp and automatically feeds passwords from a machine-bound encrypted vault.",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sshmonkey version %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func main() {
	// Check askpass mode FIRST, before any cobra initialization.
	// This ensures fast response when SSH invokes us as SSH_ASKPASS.
	if askpass.IsAskpassMode() {
		if err := askpass.RunAskpass(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
