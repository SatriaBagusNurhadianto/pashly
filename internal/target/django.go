package target

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
)

// djangoAdapter implements Django's PBKDF2PasswordHasher format:
// pbkdf2_sha256$<iterations>$<salt>$<base64 hash>. Reference: Django
// password management – hashers.
//
// Django's salt is stored as literal text between $ delimiters (not
// base64), generated from a printable base62 alphabet — see
// randomASCIIString. That constraint means this adapter cannot reuse an
// arbitrary binary-salted hash.Result produced by the generic
// pbkdf2-sha256 algorithm; it derives its own salt directly.
type djangoAdapter struct{ rawPassword }

func (djangoAdapter) Name() string        { return NameDjango }
func (djangoAdapter) AlgorithmID() string { return hash.IDPbkdf2Sha256 }

// djangoDefaultIterations tracks Django's own current PBKDF2PasswordHasher
// default, which upstream periodically raises; operators should override
// via --iterations if their Django version's default differs.
const djangoDefaultIterations = 720000

const djangoSaltLength = 12

func (djangoAdapter) DefaultParams() hash.Params {
	return hash.Params{Iterations: djangoDefaultIterations, SaltLength: djangoSaltLength, KeyLength: 32}
}

func (d djangoAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	if params.Iterations == 0 {
		params.Iterations = djangoDefaultIterations
	}
	if params.SaltLength == 0 {
		params.SaltLength = djangoSaltLength
	}
	if params.KeyLength == 0 {
		params.KeyLength = 32
	}
	salt, err := randomASCIIString(params.SaltLength)
	if err != nil {
		return hash.Result{}, err
	}
	key, err := hash.PBKDF2WithSalt("sha256", password, []byte(salt), params.Iterations, params.KeyLength)
	if err != nil {
		return hash.Result{}, err
	}
	return hash.Result{
		Algorithm: d.AlgorithmID(),
		Params:    params,
		Salt:      []byte(salt),
		Key:       key,
	}, nil
}

func (d djangoAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != d.AlgorithmID() {
		return "", fmt.Errorf("django target requires a pbkdf2-sha256 hash.Result, got %q", r.Algorithm)
	}
	if strings.ContainsRune(string(r.Salt), '$') {
		return "", fmt.Errorf("django salt must not contain '$'")
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", r.Params.Iterations, r.Salt, base64.StdEncoding.EncodeToString(r.Key)), nil
}

func (d djangoAdapter) Decode(encoded string) (hash.Result, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return hash.Result{}, fmt.Errorf("not a valid Django pbkdf2_sha256 hash")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return hash.Result{}, fmt.Errorf("parsing django iterations: %w", err)
	}
	if err := hash.ValidatePBKDF2Iterations(iterations); err != nil {
		return hash.Result{}, err
	}
	salt := parts[2]
	key, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return hash.Result{}, fmt.Errorf("decoding django hash: %w", err)
	}
	return hash.Result{
		Algorithm: d.AlgorithmID(),
		Params:    hash.Params{Iterations: iterations, SaltLength: len(salt), KeyLength: len(key)},
		Salt:      []byte(salt),
		Key:       key,
	}, nil
}
