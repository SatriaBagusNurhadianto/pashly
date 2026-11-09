package target

import (
	"testing"

	"github.com/cerberauth/pashly/internal/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPassword = "correct horse battery staple"

func TestAllAdaptersRoundtrip(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			adapter, err := Get(name)
			require.NoError(t, err)

			r, err := adapter.Hash([]byte(testPassword), adapter.DefaultParams())
			require.NoError(t, err)
			assert.Equal(t, adapter.AlgorithmID(), r.Algorithm)

			encoded, err := adapter.Encode(r)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			decoded, err := adapter.Decode(encoded)
			require.NoError(t, err)
			if adapter.AlgorithmID() != "bcrypt" {
				// bcrypt's minor version byte ($2a$ vs $2b$/$2y$) may
				// legitimately change across a target round-trip; only
				// non-bcrypt algorithms guarantee byte-identical salt/key.
				assert.Equal(t, r.Key, decoded.Key)
				assert.Equal(t, r.Salt, decoded.Salt)
			}

			// The decoded Result should verify against the underlying
			// canonical algorithm.
			algo, err := hash.Get(adapter.AlgorithmID())
			require.NoError(t, err)

			var canonical string
			switch adapter.AlgorithmID() {
			case "bcrypt":
				canonical = string(decoded.Key)
			default:
				canonical, err = algo.Encode(decoded)
				require.NoError(t, err)
			}

			ok, err := algo.Verify(adapter.PreparePassword([]byte(testPassword)), canonical)
			require.NoError(t, err)
			assert.True(t, ok)

			ok, err = algo.Verify(adapter.PreparePassword([]byte("wrong password")), canonical)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

// TestAuth0EncodeFormat checks the exact JSON shape expected by Auth0's
// bulk import custom_password_hash schema.
func TestAuth0EncodeFormat(t *testing.T) {
	adapter, err := Get("auth0")
	require.NoError(t, err)

	r, err := adapter.Hash([]byte(testPassword), adapter.DefaultParams())
	require.NoError(t, err)

	encoded, err := adapter.Encode(r)
	require.NoError(t, err)
	assert.Contains(t, encoded, `"algorithm": "bcrypt"`)
	assert.Contains(t, encoded, `"encoding": "utf8"`)
}

// TestOktaEncodeFormat checks the exact JSON shape expected by Okta's
// ImportHashedPassword schema.
func TestOktaEncodeFormat(t *testing.T) {
	adapter, err := Get("okta")
	require.NoError(t, err)

	r, err := adapter.Hash([]byte(testPassword), adapter.DefaultParams())
	require.NoError(t, err)

	encoded, err := adapter.Encode(r)
	require.NoError(t, err)
	assert.Contains(t, encoded, `"saltOrder": "PREFIX"`)
	assert.Contains(t, encoded, `"workFactor"`)
}

func TestDjangoEncodeFormat(t *testing.T) {
	adapter, err := Get("django")
	require.NoError(t, err)

	r, err := adapter.Hash([]byte(testPassword), hash.Params{Iterations: 1000})
	require.NoError(t, err)

	encoded, err := adapter.Encode(r)
	require.NoError(t, err)
	assert.Regexp(t, `^pbkdf2_sha256\$1000\$[a-zA-Z0-9]{12}\$`, encoded)
}

func TestWordpressEncodeFormat(t *testing.T) {
	adapter, err := Get("wordpress")
	require.NoError(t, err)

	r, err := adapter.Hash([]byte(testPassword), hash.Params{Cost: 4})
	require.NoError(t, err)

	encoded, err := adapter.Encode(r)
	require.NoError(t, err)
	assert.Regexp(t, `^\$wp\$2y\$04\$`, encoded)

	// The stored bcrypt is over the pre-hashed password, not the raw one.
	bcrypt, err := hash.Get(hash.IDBcrypt)
	require.NoError(t, err)
	ok, err := bcrypt.Verify(adapter.PreparePassword([]byte(testPassword)), string(r.Key))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = bcrypt.Verify([]byte(testPassword), string(r.Key))
	require.NoError(t, err)
	assert.False(t, ok)
}

// wordpress68Hash was produced by PHP 8.3 running WordPress 6.8's
// wp_hash_password() code path for testPassword (cost 4):
// '$wp' . password_hash(base64_encode(hash_hmac('sha384', trim($password), 'wp-sha384', true)), PASSWORD_BCRYPT).
const wordpress68Hash = "$wp$2y$04$CJbTd7D7r3NEIEQhv9x0zuuZ.dw.4ZT4whKecDlb0xsd8KKVydw2K"

func TestWordpress68KnownAnswer(t *testing.T) {
	adapter, err := Get("wordpress")
	require.NoError(t, err)

	r, err := adapter.Decode(wordpress68Hash)
	require.NoError(t, err)

	bcrypt, err := hash.Get(hash.IDBcrypt)
	require.NoError(t, err)
	ok, err := bcrypt.Verify(adapter.PreparePassword([]byte(testPassword)), string(r.Key))
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = bcrypt.Verify(adapter.PreparePassword([]byte("wrong")), string(r.Key))
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestAspnetIdentityKnownVector cross-validates against a real
// Microsoft.Extensions.Identity.Core 8.0.10 PasswordHasher<T> vector
// (dotnet SDK 8.0.131).
func TestAspnetIdentityKnownVector(t *testing.T) {
	adapter, err := Get("aspnet-identity")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"correct horse battery staple", "AQAAAAIAAYagAAAAEBfcD4cjUNB4CudYVh4hiPqZ5d5Tp8qfx4iI4RDx0QWMa3OQ46+HxACC9P+38rzRbw=="},
		{"password123", "AQAAAAIAAYagAAAAEL5LYnOQ9X2MLZU183oQp5BMNlu6IJXJ/W93KjkQW3N6N2Iml6+F7IS79ZT62KyE+Q=="},
	}

	for _, c := range cases {
		r, err := adapter.Decode(c.encoded)
		require.NoError(t, err)
		assert.Equal(t, 100000, r.Params.Iterations)
		assert.Len(t, r.Salt, 16)
		assert.Len(t, r.Key, 32)

		algo, err := hash.Get("pbkdf2-sha512")
		require.NoError(t, err)
		canonical, err := algo.Encode(r)
		require.NoError(t, err)

		ok, err := algo.Verify([]byte(c.password), canonical)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestKeycloakEncodeFormat(t *testing.T) {
	adapter, err := Get("keycloak")
	require.NoError(t, err)

	r, err := adapter.Hash([]byte(testPassword), hash.Params{Iterations: 1000})
	require.NoError(t, err)

	encoded, err := adapter.Encode(r)
	require.NoError(t, err)
	assert.Contains(t, encoded, `"type": "password"`)
	assert.Contains(t, encoded, "pbkdf2-sha256")
}

func TestTargetsRejectOutOfRangeIterations(t *testing.T) {
	cases := map[string][]string{
		NameDjango: {
			"pbkdf2_sha256$0$salt$aGFzaGhhc2g=",
			"pbkdf2_sha256$-5$salt$aGFzaGhhc2g=",
			"pbkdf2_sha256$4294967295$salt$aGFzaGhhc2g=",
		},
		NameKeycloak: {
			`{"type":"password","credentialData":"{\"hashIterations\":0,\"algorithm\":\"pbkdf2-sha256\"}","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}"}`,
			`{"type":"password","credentialData":"{\"hashIterations\":-1,\"algorithm\":\"pbkdf2-sha256\"}","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}"}`,
			`{"type":"password","credentialData":"{\"hashIterations\":4294967295,\"algorithm\":\"pbkdf2-sha256\"}","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}"}`,
		},
		NameASPNetIdentity: {
			// marker 0x01, PRF 2, iterations 0 / 0xFFFFFFFF, salt length 4.
			"AQAAAAIAAAAAAAAABHNhbHRoYXNo",
			"AQAAAAL/////AAAABHNhbHRoYXNo",
		},
	}
	for name, encodings := range cases {
		adapter, err := Get(name)
		require.NoError(t, err)
		for _, encoded := range encodings {
			_, err := adapter.Decode(encoded)
			assert.Error(t, err, "%s: %s", name, encoded)
		}
	}
}
