package cmd

import (
	"fmt"
	"time"

	"github.com/cerberauth/pashly/internal/hash"
	"github.com/cerberauth/pashly/internal/target"
	"github.com/spf13/cobra"
)

var (
	hashAlgorithm  string
	hashTarget     string
	hashCost       int
	hashIterations int
	hashMemory     int
	hashParallel   int
	hashSaltLength int
	hashKeyLength  int
	hashFormat     string

	hashPasswordFlags passwordInputFlags
)

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Hash a password",
	RunE: func(cmd *cobra.Command, args []string) error {
		if hashTarget != "" && cmd.Flags().Changed("algorithm") {
			return fmt.Errorf("--algorithm and --target are mutually exclusive; --target already selects the platform's algorithm")
		}
		if hashCost < 0 || hashIterations < 0 || hashMemory < 0 || hashParallel < 0 || hashSaltLength < 0 || hashKeyLength < 0 {
			return fmt.Errorf("--cost, --iterations, --memory, --parallelism, --salt-length, and --key-length must not be negative")
		}

		password, err := readPassword(hashPasswordFlags)
		if err != nil {
			return err
		}

		var encoded, algorithmID string

		if hashTarget != "" {
			adapter, err := target.Get(hashTarget)
			if err != nil {
				return err
			}
			algorithmID = adapter.AlgorithmID()
			params := fillMissingParams(paramsForAlgorithm(algorithmID, rawParams()), adapter.DefaultParams())

			hashStart := time.Now()
			result, err := adapter.Hash(password, params)
			if err != nil {
				return err
			}
			hashDuration.Record(cmd.Context(), time.Since(hashStart), algorithmLabel(algorithmID), targetLabel(hashTarget))
			if encoded, err = adapter.Encode(result); err != nil {
				return err
			}
		} else {
			algorithmID = hashAlgorithm
			if algorithmID == "" {
				algorithmID = hash.IDArgon2id
			}
			algo, err := hash.Get(algorithmID)
			if err != nil {
				return err
			}
			if algo.LegacyOnly() {
				return fmt.Errorf("%s: %w", algorithmID, hash.ErrLegacyHashTarget)
			}
			params := fillMissingParams(paramsForAlgorithm(algorithmID, rawParams()), algo.DefaultParams())

			hashStart := time.Now()
			result, err := algo.Hash(password, params)
			if err != nil {
				return err
			}
			hashDuration.Record(cmd.Context(), time.Since(hashStart), algorithmLabel(algorithmID), "none")
			if encoded, err = algo.Encode(result); err != nil {
				return err
			}
		}

		return printHashResult(algorithmID, encoded, hashFormat)
	},
}

// rawParams reflects the user's raw CLI flags before algorithm-specific
// reinterpretation; --iterations is deliberately left in its own field
// here and only mapped onto N/Time/Iterations by paramsForAlgorithm, since
// its meaning (scrypt log2(N) / argon2 time cost / pbkdf2 iteration count)
// depends on which algorithm is selected.
// rawParams is only reached after RunE has already rejected negative flag
// values, so these int -> uint32 conversions cannot wrap.
func rawParams() hash.Params {
	return hash.Params{
		Cost:        hashCost,
		Parallelism: uint32(hashParallel), // #nosec G115 -- validated non-negative in RunE
		SaltLength:  hashSaltLength,
		KeyLength:   hashKeyLength,
	}
}

// paramsForAlgorithm maps the shared --iterations flag onto the field the
// given algorithm actually reads.
func paramsForAlgorithm(algorithmID string, p hash.Params) hash.Params {
	switch algorithmID {
	case hash.IDScrypt:
		if hashIterations > 0 {
			p.N = 1 << hashIterations
		}
		if hashParallel > 0 {
			p.P = hashParallel
		}
	case hash.IDArgon2id, hash.IDArgon2i:
		if hashIterations > 0 {
			p.Time = uint32(hashIterations) // #nosec G115 -- validated non-negative in RunE
		}
		if hashMemory > 0 {
			p.Memory = uint32(hashMemory) // #nosec G115 -- validated non-negative in RunE
		}
	case hash.IDPbkdf2Sha1, hash.IDPbkdf2Sha256, hash.IDPbkdf2Sha512:
		if hashIterations > 0 {
			p.Iterations = hashIterations
		}
	}
	return p
}

// fillMissingParams overlays defaults onto any zero-valued field of p, so
// unset flags fall back to the algorithm/target's defaults.
func fillMissingParams(p, defaults hash.Params) hash.Params {
	if p.Cost == 0 {
		p.Cost = defaults.Cost
	}
	if p.SaltLength == 0 {
		p.SaltLength = defaults.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = defaults.KeyLength
	}
	if p.Parallelism == 0 {
		p.Parallelism = defaults.Parallelism
	}
	if p.N == 0 {
		p.N = defaults.N
	}
	if p.R == 0 {
		p.R = defaults.R
	}
	if p.P == 0 {
		p.P = defaults.P
	}
	if p.Memory == 0 {
		p.Memory = defaults.Memory
	}
	if p.Time == 0 {
		p.Time = defaults.Time
	}
	if p.Iterations == 0 {
		p.Iterations = defaults.Iterations
	}
	return p
}

func printHashResult(algorithmID, encoded, format string) error {
	switch format {
	case "", "raw":
		fmt.Println(encoded)
		return nil
	case formatJSON:
		return printJSON(map[string]string{
			"algorithm": algorithmID,
			"hash":      encoded,
		})
	default:
		return fmt.Errorf("unknown --format %q (expected raw or json)", format)
	}
}

func init() {
	hashCmd.Flags().StringVarP(&hashAlgorithm, "algorithm", "a", "argon2id", fmt.Sprintf("hash algorithm (%v)", hashableAlgorithmIDs()))
	hashCmd.Flags().StringVar(&hashTarget, "target", "", fmt.Sprintf("platform preset, overrides --algorithm (%v)", target.Names()))
	hashCmd.Flags().IntVar(&hashCost, "cost", 0, "bcrypt cost factor (4-31)")
	hashCmd.Flags().IntVar(&hashIterations, "iterations", 0, "scrypt N as log2(N) / argon2 time cost / pbkdf2 iteration count")
	hashCmd.Flags().IntVar(&hashMemory, "memory", 0, "argon2 memory in KiB")
	hashCmd.Flags().IntVar(&hashParallel, "parallelism", 0, "argon2 parallelism")
	hashCmd.Flags().IntVar(&hashSaltLength, "salt-length", 0, "salt length in bytes")
	hashCmd.Flags().IntVar(&hashKeyLength, "key-length", 0, "derived key length in bytes")
	hashCmd.Flags().StringVar(&hashFormat, "format", "raw", "output format: raw | json")

	hashCmd.Flags().StringVar(&hashPasswordFlags.password, "password", "", "password to hash (warning: prefer --stdin or --password-file)")
	hashCmd.Flags().BoolVar(&hashPasswordFlags.stdin, "stdin", false, "read password from stdin")
	hashCmd.Flags().StringVar(&hashPasswordFlags.passwordFile, "password-file", "", "read password from file")
}

func hashableAlgorithmIDs() []string {
	var out []string
	for _, id := range hash.IDs() {
		algo, err := hash.Get(id)
		if err != nil || algo.LegacyOnly() {
			continue
		}
		out = append(out, id)
	}
	return out
}
