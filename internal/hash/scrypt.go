package hash

import (
	"fmt"
	"math"
	"regexp"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

// scryptRE matches pashly's scrypt PHC-style convention:
// $scrypt$ln=<log2N>,r=<r>,p=<p>$<salt>$<hash>
// (there is no single dominant PHC form for scrypt in the wild; this
// follows the "ln" convention used by Rust's scrypt crate and passlib).
var scryptRE = regexp.MustCompile(`^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`)

// scryptDefaults follows the current OWASP Password Storage Cheat Sheet:
// N=2^17 (131072), r=8, p=1.
var scryptDefaultParams = Params{N: 1 << 17, R: 8, P: 1, SaltLength: 16, KeyLength: 32}

type scryptAlgorithm struct{}

func (scryptAlgorithm) ID() string       { return IDScrypt }
func (scryptAlgorithm) LegacyOnly() bool { return false }

func (scryptAlgorithm) DefaultParams() Params { return scryptDefaultParams }

func (s scryptAlgorithm) Hash(password []byte, params Params) (Result, error) {
	p := fillScryptDefaults(params)
	if err := validateScryptParams(p.N, p.R, p.P); err != nil {
		return Result{}, err
	}
	salt, err := randomSalt(p.SaltLength)
	if err != nil {
		return Result{}, err
	}
	key, err := scrypt.Key(password, salt, p.N, p.R, p.P, p.KeyLength)
	if err != nil {
		return Result{}, err
	}
	return Result{Algorithm: s.ID(), Params: p, Salt: salt, Key: key}, nil
}

func fillScryptDefaults(p Params) Params {
	d := scryptDefaultParams
	if p.N == 0 {
		p.N = d.N
	}
	if p.R == 0 {
		p.R = d.R
	}
	if p.P == 0 {
		p.P = d.P
	}
	if p.SaltLength == 0 {
		p.SaltLength = d.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = d.KeyLength
	}
	return p
}

func (scryptAlgorithm) Encode(r Result) (string, error) {
	ln := int(math.Round(math.Log2(float64(r.Params.N))))
	return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s",
		ln, r.Params.R, r.Params.P, b64Encode(r.Salt), b64Encode(r.Key)), nil
}

func (s scryptAlgorithm) Decode(encoded string) (Result, error) {
	m := scryptRE.FindStringSubmatch(encoded)
	if m == nil {
		return Result{}, fmt.Errorf("not a valid scrypt hash")
	}
	ln, err := strconv.Atoi(m[1])
	if err != nil || ln < 1 || ln > scryptMaxLn {
		return Result{}, fmt.Errorf("scrypt ln must be between 1 and %d, got %s", scryptMaxLn, m[1])
	}
	r, err := strconv.Atoi(m[2])
	if err != nil {
		return Result{}, fmt.Errorf("invalid scrypt r %q: %w", m[2], err)
	}
	p, err := strconv.Atoi(m[3])
	if err != nil {
		return Result{}, fmt.Errorf("invalid scrypt p %q: %w", m[3], err)
	}
	if err := validateScryptParams(1<<ln, r, p); err != nil {
		return Result{}, err
	}
	salt, err := b64Decode(m[4])
	if err != nil {
		return Result{}, fmt.Errorf("decoding salt: %w", err)
	}
	key, err := b64Decode(m[5])
	if err != nil {
		return Result{}, fmt.Errorf("decoding hash: %w", err)
	}
	return Result{
		Algorithm: s.ID(),
		Params: Params{
			N: 1 << ln, R: r, P: p,
			SaltLength: len(salt),
			KeyLength:  len(key),
		},
		Salt: salt,
		Key:  key,
	}, nil
}

func (scryptAlgorithm) Detect(encoded string) bool {
	return scryptRE.MatchString(encoded)
}

func (s scryptAlgorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := s.Decode(encoded)
	if err != nil {
		return false, err
	}
	derived, err := scrypt.Key(password, r.Salt, r.Params.N, r.Params.R, r.Params.P, len(r.Key))
	if err != nil {
		return false, err
	}
	return constantTimeEqual(derived, r.Key), nil
}
