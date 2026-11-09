package hash

import (
	"fmt"
	"math"
	"regexp"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// argon2RE matches $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> and the
// argon2i equivalent.
var argon2RE = regexp.MustCompile(`^\$(argon2id|argon2i)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$`)

const argon2Version = argon2.Version // 19

// Defaults follow the current OWASP Password Storage Cheat Sheet:
// argon2id: m=19MiB (19456 KiB), t=2, p=1; argon2i: m=12MiB (12288 KiB), t=3, p=1.
var argon2Defaults = map[string]Params{
	IDArgon2id: {Memory: 19456, Time: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32},
	IDArgon2i:  {Memory: 12288, Time: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32},
}

// argon2MaxMemoryKiB caps the memory cost accepted from a hash or a flag
// (4 GiB), so an untrusted hash cannot make pashly allocate terabytes.
const argon2MaxMemoryKiB = 4 * 1024 * 1024

// validateArgon2Params rejects parameters that golang.org/x/crypto/argon2
// would panic on, or that would exhaust memory.
func validateArgon2Params(p Params) error {
	if p.Time < 1 {
		return fmt.Errorf("argon2 time cost must be at least 1, got %d", p.Time)
	}
	if p.Parallelism < 1 || p.Parallelism > 255 {
		return fmt.Errorf("argon2 parallelism must be between 1 and 255, got %d", p.Parallelism)
	}
	if uint64(p.Memory) < 8*uint64(p.Parallelism) {
		return fmt.Errorf("argon2 memory must be at least 8*parallelism (%d KiB), got %d", 8*p.Parallelism, p.Memory)
	}
	if p.Memory > argon2MaxMemoryKiB {
		return fmt.Errorf("argon2 memory must be at most %d KiB, got %d", argon2MaxMemoryKiB, p.Memory)
	}
	return nil
}

type argon2Algorithm struct {
	variant string // "argon2id" or "argon2i"
}

func (a argon2Algorithm) ID() string     { return a.variant }
func (argon2Algorithm) LegacyOnly() bool { return false }

func (a argon2Algorithm) DefaultParams() Params {
	return argon2Defaults[a.variant]
}

func (a argon2Algorithm) Hash(password []byte, params Params) (Result, error) {
	p := fillArgon2Defaults(a.variant, params)
	if err := validateArgon2Params(p); err != nil {
		return Result{}, err
	}
	salt, err := randomSalt(p.SaltLength)
	if err != nil {
		return Result{}, err
	}
	key, err := deriveArgon2(a.variant, password, salt, p)
	if err != nil {
		return Result{}, err
	}
	return Result{Algorithm: a.ID(), Params: p, Salt: salt, Key: key}, nil
}

func fillArgon2Defaults(variant string, p Params) Params {
	d := argon2Defaults[variant]
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Time == 0 {
		p.Time = d.Time
	}
	if p.Parallelism == 0 {
		p.Parallelism = d.Parallelism
	}
	if p.SaltLength == 0 {
		p.SaltLength = d.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = d.KeyLength
	}
	return p
}

// deriveArgon2 validates p itself so the narrowing conversions below are
// always bounded, whichever caller (Hash or Verify) it comes from.
func deriveArgon2(variant string, password, salt []byte, p Params) ([]byte, error) {
	if err := validateArgon2Params(p); err != nil {
		return nil, err
	}
	if p.Parallelism > 255 || p.KeyLength < 0 || uint64(p.KeyLength) > math.MaxUint32 {
		return nil, fmt.Errorf("argon2 parameters out of range")
	}
	parallelism := uint8(p.Parallelism)
	keyLen := uint32(p.KeyLength)
	if variant == IDArgon2id {
		return argon2.IDKey(password, salt, p.Time, p.Memory, parallelism, keyLen), nil
	}
	return argon2.Key(password, salt, p.Time, p.Memory, parallelism, keyLen), nil
}

func (a argon2Algorithm) Encode(r Result) (string, error) {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		a.variant, argon2Version, r.Params.Memory, r.Params.Time, r.Params.Parallelism,
		b64Encode(r.Salt), b64Encode(r.Key)), nil
}

func (a argon2Algorithm) Decode(encoded string) (Result, error) {
	m := argon2RE.FindStringSubmatch(encoded)
	if m == nil || m[1] != a.variant {
		return Result{}, fmt.Errorf("not a valid %s hash", a.variant)
	}
	memory, err := strconv.ParseUint(m[3], 10, 32)
	if err != nil {
		return Result{}, fmt.Errorf("invalid argon2 memory %q: %w", m[3], err)
	}
	time, err := strconv.ParseUint(m[4], 10, 32)
	if err != nil {
		return Result{}, fmt.Errorf("invalid argon2 time cost %q: %w", m[4], err)
	}
	parallelism, err := strconv.ParseUint(m[5], 10, 32)
	if err != nil {
		return Result{}, fmt.Errorf("invalid argon2 parallelism %q: %w", m[5], err)
	}
	params := Params{
		Memory:      uint32(memory),      // #nosec G115 -- parsed with bitSize 32
		Time:        uint32(time),        // #nosec G115 -- parsed with bitSize 32
		Parallelism: uint32(parallelism), // #nosec G115 -- parsed with bitSize 32
	}
	if err := validateArgon2Params(params); err != nil {
		return Result{}, err
	}
	salt, err := b64Decode(m[6])
	if err != nil {
		return Result{}, fmt.Errorf("decoding salt: %w", err)
	}
	key, err := b64Decode(m[7])
	if err != nil {
		return Result{}, fmt.Errorf("decoding hash: %w", err)
	}
	params.SaltLength = len(salt)
	params.KeyLength = len(key)
	return Result{
		Algorithm: a.ID(),
		Params:    params,
		Salt:      salt,
		Key:       key,
	}, nil
}

func (a argon2Algorithm) Detect(encoded string) bool {
	m := argon2RE.FindStringSubmatch(encoded)
	return m != nil && m[1] == a.variant
}

func (a argon2Algorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := a.Decode(encoded)
	if err != nil {
		return false, err
	}
	derived, err := deriveArgon2(a.variant, password, r.Salt, r.Params)
	if err != nil {
		return false, err
	}
	return constantTimeEqual(derived, r.Key), nil
}
