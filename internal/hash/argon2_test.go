package hash

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// TestArgon2idReferenceVectors validates the raw Argon2id derivation
// against vectors generated with the P-H-C reference CLI
// (github.com/P-H-C/phc-winner-argon2), password="password",
// salt="somesalt", no secret/associated data.
func TestArgon2idReferenceVectors(t *testing.T) {
	password, salt := []byte("password"), []byte("somesalt")
	cases := []struct {
		time, memory uint32
		threads      uint8
		expectedHex  string
	}{
		{time: 1, memory: 64, threads: 1, expectedHex: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{time: 2, memory: 64, threads: 1, expectedHex: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"},
		{time: 2, memory: 64, threads: 2, expectedHex: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"},
	}
	for _, c := range cases {
		want, err := hex.DecodeString(c.expectedHex)
		require.NoError(t, err)
		got := argon2.IDKey(password, salt, c.time, c.memory, c.threads, uint32(len(want)))
		assert.Equal(t, c.expectedHex, hex.EncodeToString(got))
	}
}

func TestArgon2EncodeDecodeVerifyRoundtrip(t *testing.T) {
	for _, variant := range []string{"argon2id", "argon2i"} {
		t.Run(variant, func(t *testing.T) {
			algo, err := Get(variant)
			require.NoError(t, err)

			r, err := algo.Hash([]byte("correct horse battery staple"), Params{Memory: 64, Time: 1, Parallelism: 1})
			require.NoError(t, err)

			encoded, err := algo.Encode(r)
			require.NoError(t, err)
			assert.Contains(t, encoded, "$"+variant+"$v=19$m=64,t=1,p=1$")
			assert.True(t, algo.Detect(encoded))

			ok, err := algo.Verify([]byte("correct horse battery staple"), encoded)
			require.NoError(t, err)
			assert.True(t, ok)

			ok, err = algo.Verify([]byte("wrong"), encoded)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestArgon2DetectDistinguishesVariants(t *testing.T) {
	id, err := Get("argon2id")
	require.NoError(t, err)
	i, err := Get("argon2i")
	require.NoError(t, err)

	rID, err := id.Hash([]byte("pw"), Params{Memory: 64, Time: 1, Parallelism: 1})
	require.NoError(t, err)
	encodedID, err := id.Encode(rID)
	require.NoError(t, err)

	assert.True(t, id.Detect(encodedID))
	assert.False(t, i.Detect(encodedID))
}

// TestArgon2DecodeRejectsUnsafeParams covers malformed or hostile
// parameters that would otherwise panic in golang.org/x/crypto/argon2 or
// exhaust memory.
func TestArgon2DecodeRejectsUnsafeParams(t *testing.T) {
	algo, err := Get("argon2id")
	require.NoError(t, err)

	cases := map[string]string{
		"zero time":         "$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"zero parallelism":  "$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
		"parallelism > 255": "$argon2id$v=19$m=4096,t=1,p=256$c2FsdHNhbHQ$aGFzaGhhc2g",
		"memory < 8*p":      "$argon2id$v=19$m=15,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"memory too large":  "$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"memory overflow":   "$argon2id$v=19$m=99999999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"time overflow":     "$argon2id$v=19$m=8,t=99999999999,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := algo.Decode(encoded)
			assert.Error(t, err)

			assert.NotPanics(t, func() {
				_, err = algo.Verify([]byte("x"), encoded)
			})
			assert.Error(t, err)
		})
	}
}

func TestArgon2HashRejectsUnsafeParams(t *testing.T) {
	algo, err := Get("argon2id")
	require.NoError(t, err)

	_, err = algo.Hash([]byte("pw"), Params{Memory: 8, Time: 1, Parallelism: 2})
	assert.Error(t, err)
	_, err = algo.Hash([]byte("pw"), Params{Memory: argon2MaxMemoryKiB + 1, Time: 1, Parallelism: 1})
	assert.Error(t, err)
}
