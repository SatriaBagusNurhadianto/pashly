package hash

import "fmt"

// Upper bounds applied when decoding hashes, which during a migration come
// from external, untrusted dumps: a single hostile hash must not be able to
// exhaust memory or pin a CPU for hours.
const (
	// MaxPBKDF2Iterations is far above every platform default (the
	// highest, OWASP's pbkdf2-sha1 recommendation, is 1.3M).
	MaxPBKDF2Iterations = 100_000_000

	// scryptMaxMemoryBytes caps scrypt's 128*r*N working memory (4 GiB).
	scryptMaxMemoryBytes = 4 << 30
	// scryptMaxLn bounds log2(N) before computing 1<<ln.
	scryptMaxLn = 32
)

// ValidatePBKDF2Iterations rejects zero, negative or excessive PBKDF2
// iteration counts.
func ValidatePBKDF2Iterations(iterations int) error {
	if iterations < 1 || iterations > MaxPBKDF2Iterations {
		return fmt.Errorf("pbkdf2 iterations must be between 1 and %d, got %d", MaxPBKDF2Iterations, iterations)
	}
	return nil
}

// validateScryptParams rejects scrypt parameters that are invalid or would
// need more than scryptMaxMemoryBytes of memory.
func validateScryptParams(n, r, p int) error {
	if n <= 1 || n&(n-1) != 0 {
		return fmt.Errorf("scrypt N must be a power of two greater than 1, got %d", n)
	}
	if r < 1 || p < 1 {
		return fmt.Errorf("scrypt r and p must be at least 1, got r=%d p=%d", r, p)
	}
	if uint64(r)*uint64(p) >= 1<<30 {
		return fmt.Errorf("scrypt r*p must be less than 2^30, got r=%d p=%d", r, p)
	}
	if uint64(n) > scryptMaxMemoryBytes/(128*uint64(r)) {
		return fmt.Errorf("scrypt parameters N=%d r=%d need more than %d bytes of memory", n, r, scryptMaxMemoryBytes)
	}
	return nil
}
