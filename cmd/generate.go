package cmd

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/pashly/internal/genpass"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
)

// Generate metrics, declared in the Argvio catalog. Only the charset preset and the output
// format, both fixed lists, and the requested sizes are sent, never a password.
var (
	generateRuns    = argvio.NewCounter("generate.run", argvio.Dims("charset", "format", "ambiguous"))
	generateLengths = argvio.NewValue("generate.length", argvio.WithUnit(argvio.UnitCount))
	generateCounts  = argvio.NewValue("generate.count", argvio.WithUnit(argvio.UnitCount))
)

// charsetLabel is the --charset preset: "custom:..." is reduced to "custom" so
// the characters a user picked never leave the machine.
func charsetLabel(charset string) string {
	if strings.HasPrefix(charset, "custom:") {
		return "custom"
	}
	return telemetryx.Vocab(charset, "alnum", "alnum-symbols")
}

func recordGenerate(ctx context.Context) {
	ambiguous := "included"
	if generateNoAmbiguous {
		ambiguous = "excluded"
	}
	generateRuns.Add(ctx, 1, charsetLabel(generateCharset), telemetryx.Vocab(generateFormat, "plain", formatJSON, "csv"), ambiguous)
	generateLengths.Record(ctx, float64(generateLength))
	generateCounts.Record(ctx, float64(generateCount))
}

var (
	generateCount       int
	generateLength      int
	generateCharset     string
	generateNoAmbiguous bool
	generateFormat      string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate one or more random passwords",
	RunE: func(cmd *cobra.Command, args []string) error {
		alphabet, err := genpass.Alphabet(generateCharset, generateNoAmbiguous)
		if err != nil {
			return err
		}

		passwords, err := genpass.GenerateMany(generateCount, generateLength, alphabet)
		if err != nil {
			return err
		}

		recordGenerate(cmd.Context())
		return printPasswords(passwords, generateFormat)
	},
}

func printPasswords(passwords []string, format string) error {
	switch format {
	case "", "plain":
		for _, p := range passwords {
			fmt.Println(p)
		}
		return nil

	case formatJSON:
		return printJSON(passwords)

	case "csv":
		w := csv.NewWriter(os.Stdout)
		if err := w.Write([]string{"password"}); err != nil {
			return err
		}
		for _, p := range passwords {
			if err := w.Write([]string{p}); err != nil {
				return err
			}
		}
		w.Flush()
		return w.Error()

	default:
		return fmt.Errorf("unknown --format %q (expected plain, json, or csv)", format)
	}
}

func init() {
	generateCmd.Flags().IntVarP(&generateCount, "count", "n", 1, "number of passwords to generate")
	generateCmd.Flags().IntVarP(&generateLength, "length", "l", 20, "password length")
	generateCmd.Flags().StringVar(&generateCharset, "charset", "alnum-symbols", `charset: alnum | alnum-symbols | custom:"..."`)
	generateCmd.Flags().BoolVar(&generateNoAmbiguous, "no-ambiguous", false, "exclude visually ambiguous characters")
	generateCmd.Flags().StringVar(&generateFormat, "format", "plain", "output format: plain | json | csv")
}
