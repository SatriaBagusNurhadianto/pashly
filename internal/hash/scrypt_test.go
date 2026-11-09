package hash

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/scrypt"
)

// TestScryptRFC7914Vectors validates the raw scrypt derivation against the
// RFC 7914 §12 test vectors. The N=1048576 vector is skipped under -short.
func TestScryptRFC7914Vectors(t *testing.T) {
	cases := []struct {
		name           string
		password, salt string
		n, r, p, keyLn int
		expectedHex    string
		slow           bool
	}{
		{
			name: "empty", password: "", salt: "", n: 16, r: 1, p: 1, keyLn: 64,
			expectedHex: "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
		},
		{
			name: "password", password: "password", salt: "NaCl", n: 1024, r: 8, p: 16, keyLn: 64,
			expectedHex: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
		},
		{
			name: "pleaseletmein", password: "pleaseletmein", salt: "SodiumChloride", n: 16384, r: 8, p: 1, keyLn: 64,
			expectedHex: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
		},
		{
			name: "stress", password: "pleaseletmein", salt: "SodiumChloride", n: 1048576, r: 8, p: 1, keyLn: 64,
			expectedHex: "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
			slow:        true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.slow && testing.Short() {
				t.Skip("skipping slow N=1048576 vector under -short")
			}
			got, err := scrypt.Key([]byte(c.password), []byte(c.salt), c.n, c.r, c.p, c.keyLn)
			require.NoError(t, err)
			assert.Equal(t, c.expectedHex, hex.EncodeToString(got))
		})
	}
}

func TestScryptEncodeDecodeVerifyRoundtrip(t *testing.T) {
	algo, err := Get("scrypt")
	require.NoError(t, err)

	r, err := algo.Hash([]byte("correct horse battery staple"), Params{N: 16384, R: 8, P: 1})
	require.NoError(t, err)

	encoded, err := algo.Encode(r)
	require.NoError(t, err)
	assert.Regexp(t, `^\$scrypt\$ln=14,r=8,p=1\$`, encoded)
	assert.True(t, algo.Detect(encoded))

	ok, err := algo.Verify([]byte("correct horse battery staple"), encoded)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = algo.Verify([]byte("wrong"), encoded)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestScryptDecodeRejectsUnsafeParams(t *testing.T) {
	algo, err := Get("scrypt")
	require.NoError(t, err)

	cases := map[string]string{
		"ln zero":        "$scrypt$ln=0,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"ln overflow":    "$scrypt$ln=63,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"ln huge":        "$scrypt$ln=99999999999999999999,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"memory too big": "$scrypt$ln=40,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"r zero":         "$scrypt$ln=4,r=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"p zero":         "$scrypt$ln=4,r=8,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
		"r*p too large":  "$scrypt$ln=1,r=1,p=1073741824$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := algo.Decode(encoded)
			assert.Error(t, err)
			_, err = algo.Verify([]byte("x"), encoded)
			assert.Error(t, err)
		})
	}
}
