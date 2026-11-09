package hash

import (
	"crypto/sha1" //nolint:gosec // RFC 6070 test vectors are defined in terms of SHA-1
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
)

// TestPBKDF2SHA1RFC6070 validates the raw PBKDF2-HMAC-SHA1 derivation
// against RFC 6070 test vectors before trusting pashly's own encoding on
// top of it.
func TestPBKDF2SHA1RFC6070(t *testing.T) {
	cases := []struct {
		password, salt string
		iter, keyLen   int
		expectedHex    string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
	}
	for _, c := range cases {
		got := pbkdf2.Key([]byte(c.password), []byte(c.salt), c.iter, c.keyLen, sha1.New)
		assert.Equal(t, c.expectedHex, hex.EncodeToString(got))
	}
}

func TestPBKDF2EncodeDecodeVerifyRoundtrip(t *testing.T) {
	for _, variant := range []string{"sha1", "sha256", "sha512"} {
		t.Run(variant, func(t *testing.T) {
			algo, err := Get("pbkdf2-" + variant)
			require.NoError(t, err)

			r, err := algo.Hash([]byte("correct horse battery staple"), Params{Iterations: 1000})
			require.NoError(t, err)

			encoded, err := algo.Encode(r)
			require.NoError(t, err)
			assert.True(t, algo.Detect(encoded))

			ok, err := algo.Verify([]byte("correct horse battery staple"), encoded)
			require.NoError(t, err)
			assert.True(t, ok)

			ok, err = algo.Verify([]byte("wrong password"), encoded)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestPBKDF2Detect(t *testing.T) {
	algo, err := Get("pbkdf2-sha256")
	require.NoError(t, err)
	assert.True(t, algo.Detect("$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2g"))
	assert.False(t, algo.Detect("$pbkdf2-sha1$i=600000$c2FsdHNhbHQ$aGFzaGhhc2g"))
	assert.False(t, algo.Detect("not a hash"))
}

func TestPBKDF2DecodeRejectsOutOfRangeIterations(t *testing.T) {
	algo, err := Get("pbkdf2-sha256")
	require.NoError(t, err)

	for _, iterations := range []string{"0", "100000001", "99999999999999999999"} {
		encoded := "$pbkdf2-sha256$i=" + iterations + "$c2FsdHNhbHQ$aGFzaGhhc2g"
		_, err := algo.Decode(encoded)
		assert.Error(t, err, "iterations %s", iterations)
		_, err = algo.Verify([]byte("x"), encoded)
		assert.Error(t, err, "iterations %s", iterations)
	}

	_, err = algo.Hash([]byte("x"), Params{Iterations: MaxPBKDF2Iterations + 1})
	assert.Error(t, err)
}
