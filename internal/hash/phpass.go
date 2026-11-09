package hash

import (
	"crypto/md5" //nolint:gosec // phpass is a legacy, verify/info-only format (see threat model)
	"fmt"
	"regexp"
	"strings"
)

// phpassRE matches the Openwall portable hash format used by WordPress
// (< 6.8), phpBB3 and Drupal 7: $P$<count char><8-char salt><22-char hash>
// ($H$ is the same algorithm under an alternate prefix).
var phpassRE = regexp.MustCompile(`^\$[PH]\$([./0-9A-Za-z])([./0-9A-Za-z]{8})([./0-9A-Za-z]{22})$`)

// phpassMinCountLog2 and phpassMaxCountLog2 are the bounds enforced by the
// reference phpass implementation (crypt_private); anything outside them is
// rejected rather than computed.
const (
	phpassMinCountLog2 = 7
	phpassMaxCountLog2 = 30
)

// phpassAlgorithm implements the legacy phpass portable hash for
// verify/info only; it is never offered as a hash target
// (WordPress's current default is bcrypt, see internal/target/wordpress.go).
type phpassAlgorithm struct{}

func (phpassAlgorithm) ID() string            { return IDPhpass }
func (phpassAlgorithm) LegacyOnly() bool      { return true }
func (phpassAlgorithm) DefaultParams() Params { return Params{} }

func (phpassAlgorithm) Hash([]byte, Params) (Result, error) {
	return Result{}, ErrLegacyHashTarget
}

func (phpassAlgorithm) Encode(Result) (string, error) {
	return "", ErrLegacyHashTarget
}

func (a phpassAlgorithm) Decode(encoded string) (Result, error) {
	m := phpassRE.FindStringSubmatch(encoded)
	if m == nil {
		return Result{}, fmt.Errorf("not a valid phpass hash")
	}
	countLog2 := strings.IndexByte(itoa64, m[1][0])
	if countLog2 < phpassMinCountLog2 || countLog2 > phpassMaxCountLog2 {
		return Result{}, fmt.Errorf("phpass count_log2 must be between %d and %d, got %d",
			phpassMinCountLog2, phpassMaxCountLog2, countLog2)
	}
	return Result{
		Algorithm: a.ID(),
		Params:    Params{Iterations: 1 << countLog2},
		Salt:      []byte(m[2]),
		Key:       []byte(m[3]),
	}, nil
}

func (phpassAlgorithm) Detect(encoded string) bool {
	return phpassRE.MatchString(encoded)
}

func (a phpassAlgorithm) Verify(password []byte, encoded string) (bool, error) {
	r, err := a.Decode(encoded)
	if err != nil {
		return false, err
	}
	computed := phpassDigest(password, r.Salt, r.Params.Iterations)
	return constantTimeEqual([]byte(computed), r.Key), nil
}

// phpassDigest reproduces the Openwall portable hash framework's iterated
// MD5 stretching and itoa64 encoding.
func phpassDigest(password, salt []byte, count int) string {
	h := md5.New() //nolint:gosec
	h.Write(salt)
	h.Write(password)
	digest := h.Sum(nil)

	for i := 0; i < count; i++ {
		h := md5.New() //nolint:gosec
		h.Write(digest)
		h.Write(password)
		digest = h.Sum(nil)
	}

	return phpassEncode64(digest)
}

// phpassEncode64 implements the Openwall portable hash's encode64 (a
// little-endian, 3-input-byte-to-4-output-char itoa64 packing, distinct
// from md5crypt's permuted grouping).
func phpassEncode64(input []byte) string {
	var out strings.Builder
	i := 0
	for i < len(input) {
		value := uint32(input[i])
		i++
		out.WriteByte(itoa64[value&0x3f])
		if i < len(input) {
			value |= uint32(input[i]) << 8
		}
		out.WriteByte(itoa64[(value>>6)&0x3f])
		if i >= len(input) {
			break
		}
		i++
		if i < len(input) {
			value |= uint32(input[i]) << 16
		}
		out.WriteByte(itoa64[(value>>12)&0x3f])
		if i >= len(input) {
			break
		}
		i++
		out.WriteByte(itoa64[(value>>18)&0x3f])
	}
	return out.String()
}
