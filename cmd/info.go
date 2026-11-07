package cmd

import (
	"fmt"
	"sort"

	"github.com/cerberauth/pashly/internal/hash"
	"github.com/spf13/cobra"
)

var (
	infoFormat    string
	infoAlgorithm string
)

var infoCmd = &cobra.Command{
	Use:   "info <hash>",
	Short: "Detect the algorithm, encoding, and parameters of a hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resolved, err := resolveHash(args[0], infoAlgorithm)
		if err != nil {
			return err
		}
		recordResolved(cmd.Context(), resolved, infoAlgorithm)
		return printInfo(resolved.label, resolved.algo.ID(), resolved.result, infoFormat)
	},
}

// encodingLabel describes each algorithm's canonical string encoding for
// `info` output.
const encodingPHCPassslib = "PHC-style (passlib convention)"

var encodingLabel = map[string]string{
	hash.IDBcrypt:       "bcrypt native ($2a$/$2b$/$2y$)",
	hash.IDArgon2id:     "PHC string format",
	hash.IDArgon2i:      "PHC string format",
	hash.IDScrypt:       "PHC-style (pashly convention)",
	hash.IDPbkdf2Sha1:   encodingPHCPassslib,
	hash.IDPbkdf2Sha256: encodingPHCPassslib,
	hash.IDPbkdf2Sha512: encodingPHCPassslib,
	hash.IDMD5Crypt:     "legacy md5crypt ($1$)",
	hash.IDPhpass:       "legacy phpass portable hash ($P$/$H$)",
	hash.IDSha256Crypt:  "legacy sha256-crypt ($5$)",
	hash.IDSha512Crypt:  "legacy sha512-crypt ($6$)",
}

func printInfo(label, algorithmID string, r hash.Result, format string) error {
	params := paramsToMap(algorithmID, r.Params)
	encoding := encodingLabel[algorithmID]
	if label != algorithmID {
		encoding = fmt.Sprintf("%s (underlying algorithm: %s)", encoding, algorithmID)
	}

	switch format {
	case "", "plain":
		fmt.Printf("algorithm: %s\n", label)
		fmt.Printf("encoding:  %s\n", encoding)
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s: %v\n", k, params[k])
		}
		return nil

	case formatJSON:
		return printJSON(map[string]any{
			"algorithm": label,
			"encoding":  encoding,
			"params":    params,
		})

	default:
		return fmt.Errorf("unknown --format %q (expected plain or json)", format)
	}
}

func paramsToMap(algorithmID string, p hash.Params) map[string]any {
	out := map[string]any{}
	switch algorithmID {
	case hash.IDBcrypt:
		out["cost"] = p.Cost
	case hash.IDScrypt:
		out["N"] = p.N
		out["r"] = p.R
		out["p"] = p.P
	case hash.IDArgon2id, hash.IDArgon2i:
		out["memory"] = p.Memory
		out["time"] = p.Time
		out["parallelism"] = p.Parallelism
	case hash.IDPbkdf2Sha1, hash.IDPbkdf2Sha256, hash.IDPbkdf2Sha512:
		out["iterations"] = p.Iterations
	case hash.IDPhpass, hash.IDSha256Crypt, hash.IDSha512Crypt:
		out["iterations"] = p.Iterations
	}
	if p.SaltLength > 0 {
		out["salt_length"] = p.SaltLength
	}
	if p.KeyLength > 0 {
		out["key_length"] = p.KeyLength
	}
	return out
}

func init() {
	infoCmd.Flags().StringVar(&infoFormat, "format", "plain", "output format: plain | json")
	infoCmd.Flags().StringVar(&infoAlgorithm, "algorithm", "", "override algorithm/target auto-detection")
}
