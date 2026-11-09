package target

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/cerberauth/pashly/internal/hash"
)

// aspnetIdentityAdapter implements ASP.NET Core Identity v3's
// PasswordHasher<T> binary format (base64-encoded):
//
//	byte[0]     format marker, 0x01 for v3
//	byte[1..4]  KeyDerivationPrf, big-endian uint32 (2 = HMACSHA512)
//	byte[5..8]  iteration count, big-endian uint32
//	byte[9..12] salt length, big-endian uint32
//	byte[13:]   salt, then subkey
//
// Reference: dotnet/aspnetcore Identity.Extensions.Core PasswordHasher
// source. Field layout and defaults (PRF=HMACSHA512,
// 100,000 iterations, 16-byte salt, 32-byte subkey) were confirmed against
// a real Microsoft.Extensions.Identity.Core 8.0.10 PasswordHasher<T> run
// (dotnet SDK 8.0.131). This supersedes an earlier
// assumption of HMACSHA256; empirical verification against the actual
// library takes precedence.
type aspnetIdentityAdapter struct{}

func (aspnetIdentityAdapter) Name() string        { return NameASPNetIdentity }
func (aspnetIdentityAdapter) AlgorithmID() string { return hash.IDPbkdf2Sha512 }

const (
	aspnetFormatMarkerV3 = 0x01
	aspnetPrfHMACSHA512  = 2
	aspnetDefaultIterCnt = 100000
	aspnetDefaultSaltLen = 16
	aspnetDefaultKeyLen  = 32
)

func (aspnetIdentityAdapter) DefaultParams() hash.Params {
	return hash.Params{Iterations: aspnetDefaultIterCnt, SaltLength: aspnetDefaultSaltLen, KeyLength: aspnetDefaultKeyLen}
}

func (a aspnetIdentityAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(a.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Iterations == 0 {
		params.Iterations = aspnetDefaultIterCnt
	}
	if params.SaltLength == 0 {
		params.SaltLength = aspnetDefaultSaltLen
	}
	if params.KeyLength == 0 {
		params.KeyLength = aspnetDefaultKeyLen
	}
	return algo.Hash(password, params)
}

func (a aspnetIdentityAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != a.AlgorithmID() {
		return "", fmt.Errorf("aspnet-identity target requires a pbkdf2-sha512 hash.Result, got %q", r.Algorithm)
	}
	if r.Params.Iterations < 0 {
		return "", fmt.Errorf("iterations must not be negative")
	}
	buf := make([]byte, 13+len(r.Salt)+len(r.Key))
	buf[0] = aspnetFormatMarkerV3
	binary.BigEndian.PutUint32(buf[1:5], aspnetPrfHMACSHA512)
	binary.BigEndian.PutUint32(buf[5:9], uint32(r.Params.Iterations)) // #nosec G115 -- validated non-negative above
	binary.BigEndian.PutUint32(buf[9:13], uint32(len(r.Salt)))        // #nosec G115 -- len() is always non-negative
	copy(buf[13:], r.Salt)
	copy(buf[13+len(r.Salt):], r.Key)
	return base64.StdEncoding.EncodeToString(buf), nil
}

func (a aspnetIdentityAdapter) Decode(encoded string) (hash.Result, error) {
	buf, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return hash.Result{}, fmt.Errorf("decoding base64: %w", err)
	}
	if len(buf) < 13 {
		return hash.Result{}, fmt.Errorf("aspnet-identity hash too short")
	}
	if buf[0] != aspnetFormatMarkerV3 {
		return hash.Result{}, fmt.Errorf("unsupported ASP.NET Identity format marker 0x%02x (only v3/0x01 is supported)", buf[0])
	}
	prf := binary.BigEndian.Uint32(buf[1:5])
	if prf != aspnetPrfHMACSHA512 {
		return hash.Result{}, fmt.Errorf("unsupported ASP.NET Identity PRF %d (only HMACSHA512/2 is supported)", prf)
	}
	iterations := binary.BigEndian.Uint32(buf[5:9])
	if iterations < 1 || iterations > hash.MaxPBKDF2Iterations {
		return hash.Result{}, fmt.Errorf("pbkdf2 iterations must be between 1 and %d, got %d", hash.MaxPBKDF2Iterations, iterations)
	}
	saltLen := binary.BigEndian.Uint32(buf[9:13])
	if uint32(len(buf)) < 13+saltLen { // #nosec G115 -- len() is always non-negative
		return hash.Result{}, fmt.Errorf("aspnet-identity hash truncated (salt)")
	}
	salt := buf[13 : 13+saltLen]
	key := buf[13+saltLen:]
	return hash.Result{
		Algorithm: a.AlgorithmID(),
		Params:    hash.Params{Iterations: int(iterations), SaltLength: len(salt), KeyLength: len(key)}, // #nosec G115 -- bounded by MaxPBKDF2Iterations above
		Salt:      salt,
		Key:       key,
	}, nil
}
