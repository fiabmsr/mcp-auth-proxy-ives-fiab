package fiab

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// !fiab: coût bcrypt du mot de passe admin
const adminBcryptCost = 12

// !fiab: sous-commandes de génération des secrets
func Commands() []*cobra.Command {
	hashCmd := &cobra.Command{
		Use:   "hash-password",
		Short: "Print ADMIN_PASSWORD_HASH for a password read from stdin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.ErrOrStderr(), "Mot de passe admin : ")
			line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			password := strings.TrimRight(line, "\r\n")
			if len(password) < minPasswordLength {
				return fmt.Errorf("le mot de passe doit contenir au moins %d caractères", minPasswordLength)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(password), adminBcryptCost)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr())
			fmt.Fprintf(cmd.OutOrStdout(), "ADMIN_PASSWORD_HASH=%s\n", base64.StdEncoding.EncodeToString(hash))
			return nil
		},
	}

	var account string
	secretsCmd := &cobra.Command{
		Use:   "gen-secrets",
		Short: "Print a new ENCRYPTION_KEY and ADMIN_TOTP_SECRET",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
			}
			totp, err := security.GenerateTOTPSecret()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ENCRYPTION_KEY=%s\n", base64.StdEncoding.EncodeToString(key))
			fmt.Fprintf(out, "ADMIN_TOTP_SECRET=%s\n", totp)
			fmt.Fprintf(out, "\n# A scanner ou saisir dans Google Authenticator :\n%s\n", security.TOTPURI("MCP Proxy", account, totp))
			return nil
		},
	}
	secretsCmd.Flags().StringVar(&account, "admin-username", "admin", "Account name shown in the authenticator app")

	return []*cobra.Command{hashCmd, secretsCmd}
}
