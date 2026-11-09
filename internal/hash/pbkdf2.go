package hash

import (
	"crypto/sha1" //nolint:gosec // pbkdf2-sha1 is offered for legacy interop only, never the default
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"regexp"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2RE matches $pbkdf2-<sha1|sha256|sha512>$i=<iterations>$<salt>$<hash>,
// following passlib's widely-deployed PHC id convention (there is no
// RFC-registered PHC id for pbkdf2).
var pbkdf2RE = regexp.MustCompile(`^\$pbkdf2-(sha1|sha256|sha512)\$i=(\d+)\$([^$]+)\$([^$]+)$`)

// pbkdf2Prefix is the PHC id prefix shared by every pbkdf2-* algorithm ID.
const pbkdf2Prefix = "pbkdf2-"

// pbkdf2Defaults follow the current OWASP Password Storage Cheat Sheet
// minimum iteration counts.
var pbkdf2DefaultIterations = map[string]int{
	HashSHA1:   1300000,
	HashSHA256: 600000,
	HashSHA512: 210000,
}

var pbkdf2KeyLength = map[string]int{
	HashSHA1:   20,
	HashSHA256: 32,
	HashSHA512: 64,
}

type pbkdf2Algorithm struct {
	hashName string // "sha1", "sha256", "sha512"
}

func (p pbkdf2Algorithm) ID() string     { return pbkdf2Prefix + p.hashName }
func (pbkdf2Algorithm) LegacyOnly() bool { return false }

func (p pbkdf2Algorithm) DefaultParams() Params {
	return Params{
		Iterations: pbkdf2DefaultIterations[p.hashName],
		SaltLength: 16,
		KeyLength:  pbkdf2KeyLength[p.hashName],
	}
}

func (p pbkdf2Algorithm) newHash() func() hash.Hash {
	switch p.hashName {
	case HashSHA1:
		return sha1.New
	case HashSHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

func (p pbkdf2Algorithm) Hash(password []byte, params Params) (Result, error) {
	d := p.DefaultParams()
	if params.Iterations == 0 {
		params.Iterations = d.Iterations
	}
	if params.SaltLength == 0 {
		params.SaltLength = d.SaltLength
	}
	if params.KeyLength == 0 {
		params.KeyLength = d.KeyLength
	}
	if err := ValidatePBKDF2Iterations(params.Iterations); err != nil {
		return Result{}, err
	}
	salt, err := randomSalt(params.SaltLength)
	if err != nil {
		return Result{}, err
	}
	key := pbkdf2.Key(password, salt, params.Iterations, params.KeyLength, p.newHash())
	return Result{Algorithm: p.ID(), Params: params, Salt: salt, Key: key}, nil
}

func (p pbkdf2Algorithm) Encode(r Result) (string, error) {
	return fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", p.hashName, r.Params.Iterations, b64Encode(r.Salt), b64Encode(r.Key)), nil
}

func (p pbkdf2Algorithm) Decode(encoded string) (Result, error) {
	m := pbkdf2RE.FindStringSubmatch(encoded)
	if m == nil || m[1] != p.hashName {
		return Result{}, fmt.Errorf("not a valid pbkdf2-%s hash", p.hashName)
	}
	iterations, err := strconv.Atoi(m[2])
	if err != nil {
		return Result{}, fmt.Errorf("invalid pbkdf2 iterations %q: %w", m[2], err)
	}
	if err := ValidatePBKDF2Iterations(iterations); err != nil {
		return Result{}, err
	}
	salt, err := b64Decode(m[3])
	if err != nil {
		return Result{}, fmt.Errorf("decoding salt: %w", err)
	}
	key, err := b64Decode(m[4])
	if err != nil {
		return Result{}, fmt.Errorf("decoding hash: %w", err)
	}
	return Result{
		Algorithm: p.ID(),
		Params:    Params{Iterations: iterations, SaltLength: len(salt), KeyLength: len(key)},
		Salt:      salt,
		Key:       key,
	}, nil
}

func (p pbkdf2Algorithm) Detect(encoded string) bool {
	m := pbkdf2RE.FindStringSubmatch(encoded)
	return m != nil && m[1] == p.hashName
}

// PBKDF2WithSalt derives a key using an explicit, caller-supplied salt
// rather than a freshly generated one. It exists for target adapters
// (e.g. django) whose platform requires a specific salt encoding/alphabet
// rather than raw random bytes.
func PBKDF2WithSalt(hashName string, password, salt []byte, iterations, keyLen int) ([]byte, error) {
	algo, err := Get(pbkdf2Prefix + hashName)
	if err != nil {
		return nil, err
	}
	if err := ValidatePBKDF2Iterations(iterations); err != nil {
		return nil, err
	}
	p := algo.(pbkdf2Algorithm)
	return pbkdf2.Key(password, salt, iterations, keyLen, p.newHash()), nil
}

func (p pbkdf2Algorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := p.Decode(encoded)
	if err != nil {
		return false, err
	}
	derived := pbkdf2.Key(password, r.Salt, r.Params.Iterations, len(r.Key), p.newHash())
	return constantTimeEqual(derived, r.Key), nil
}
