package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	verifyHash         string
	verifyHashFile     string
	verifyAlgorithm    string
	verifyPasswordFlag passwordInputFlags
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a password against a hash",
	Long: `Verify a password against a hash.

Exit codes: 0 = match, 1 = no match, 2 = error (usage/parse errors). This
makes verify suitable for direct use in CI scripts.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		encoded, err := readVerifyHash()
		if err != nil {
			return exitError(2, err)
		}

		password, err := readPassword(verifyPasswordFlag)
		if err != nil {
			return exitError(2, err)
		}

		resolved, err := resolveHash(encoded, verifyAlgorithm)
		if err != nil {
			return exitError(2, err)
		}
		recordResolved(cmd.Context(), resolved, verifyAlgorithm)

		ok, err := resolved.verify(password)
		if err != nil {
			return exitError(2, fmt.Errorf("verification error: %w", err))
		}

		recordVerify(cmd.Context(), resolved, ok)
		if !ok {
			fmt.Println("no match")
			return exitError(1, nil)
		}

		fmt.Println("match")
		return nil
	},
}

func readVerifyHash() (string, error) {
	set := 0
	if verifyHash != "" {
		set++
	}
	if verifyHashFile != "" {
		set++
	}
	if set == 0 {
		return "", fmt.Errorf("one of --hash or --hash-file is required")
	}
	if set > 1 {
		return "", fmt.Errorf("--hash and --hash-file are mutually exclusive")
	}
	if verifyHash != "" {
		return strings.TrimSpace(verifyHash), nil
	}
	data, err := os.ReadFile(verifyHashFile)
	if err != nil {
		return "", fmt.Errorf("reading hash file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// exitError signals a specific process exit code alongside an optional
// error to print. It is returned from RunE with SilenceUsage/SilenceErrors
// set so cobra doesn't also print the error before os.Exit.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func exitError(code int, err error) error {
	return &exitCodeError{code: code, err: err}
}

func init() {
	verifyCmd.Flags().StringVar(&verifyHash, "hash", "", "hash to verify against")
	verifyCmd.Flags().StringVar(&verifyHashFile, "hash-file", "", "read hash to verify against from file")
	verifyCmd.Flags().StringVar(&verifyAlgorithm, "algorithm", "", "override algorithm auto-detection")

	verifyCmd.Flags().StringVar(&verifyPasswordFlag.password, "password", "", "password to verify (warning: prefer --stdin or --password-file)")
	verifyCmd.Flags().BoolVar(&verifyPasswordFlag.stdin, "stdin", false, "read password from stdin")
	verifyCmd.Flags().StringVar(&verifyPasswordFlag.passwordFile, "password-file", "", "read password from file")
}
