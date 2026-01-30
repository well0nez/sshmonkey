package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"golang.org/x/term"

	"sshmonkey/internal/vault"

	"github.com/spf13/cobra"
)

var vaultPath string

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage the encrypted password vault",
	Long:  "Add, list, edit, and remove SSH credentials from the machine-bound encrypted vault.",
}

var vaultAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new credential to the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		user, _ := cmd.Flags().GetString("user")
		port, _ := cmd.Flags().GetInt("port")
		name, _ := cmd.Flags().GetString("name")

		if host == "" || user == "" {
			return fmt.Errorf("--host and --user are required")
		}

		fmt.Fprintf(os.Stderr, "Password for %s@%s: ", user, host)
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // newline after hidden input
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password := string(passwordBytes)

		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		vp := getVaultPath()
		v, salt, err := vault.Load(vp)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}

		entry := vault.Entry{
			Name:     name,
			Host:     host,
			Port:     port,
			User:     user,
			Password: password,
		}

		if err := v.Add(entry); err != nil {
			return err
		}

		if err := v.Save(vp, salt); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Added %s@%s to vault.\n", user, host)
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		vp := getVaultPath()
		v, _, err := vault.Load(vp)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}

		entries := v.List()
		if len(entries) == 0 {
			fmt.Println("No entries in vault.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tHOST\tUSER\tPORT")
		for _, e := range entries {
			portStr := ""
			if e.Port > 0 {
				portStr = fmt.Sprintf("%d", e.Port)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Name, e.Host, e.User, portStr)
		}
		w.Flush()
		return nil
	},
}

var vaultEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Change the password for an existing credential",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		user, _ := cmd.Flags().GetString("user")

		if host == "" || user == "" {
			return fmt.Errorf("--host and --user are required")
		}

		fmt.Fprintf(os.Stderr, "New password for %s@%s: ", user, host)
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password := string(passwordBytes)

		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		vp := getVaultPath()
		v, salt, err := vault.Load(vp)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}

		if err := v.Edit(host, user, password); err != nil {
			return err
		}

		if err := v.Save(vp, salt); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Updated password for %s@%s.\n", user, host)
		return nil
	},
}

var vaultRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a credential from the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		user, _ := cmd.Flags().GetString("user")

		if host == "" || user == "" {
			return fmt.Errorf("--host and --user are required")
		}

		vp := getVaultPath()
		v, salt, err := vault.Load(vp)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}

		if err := v.Remove(host, user); err != nil {
			return err
		}

		if err := v.Save(vp, salt); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Removed %s@%s from vault.\n", user, host)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultPath, "vault-path", "", "Path to vault file (default: ~/.sshmonkey/vault.enc)")

	vaultAddCmd.Flags().String("host", "", "SSH host (required)")
	vaultAddCmd.Flags().String("user", "", "SSH user (required)")
	vaultAddCmd.Flags().Int("port", 0, "SSH port (optional)")
	vaultAddCmd.Flags().String("name", "", "Entry name (optional)")

	vaultEditCmd.Flags().String("host", "", "SSH host (required)")
	vaultEditCmd.Flags().String("user", "", "SSH user (required)")

	vaultRemoveCmd.Flags().String("host", "", "SSH host (required)")
	vaultRemoveCmd.Flags().String("user", "", "SSH user (required)")

	vaultCmd.AddCommand(vaultAddCmd, vaultListCmd, vaultEditCmd, vaultRemoveCmd)
	rootCmd.AddCommand(vaultCmd)
}

func getVaultPath() string {
	if vaultPath != "" {
		return vaultPath
	}
	return vault.DefaultVaultPath()
}
