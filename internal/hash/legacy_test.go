package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMD5CryptKnownVectors cross-validates against vectors generated with
// glibc's crypt(3) (an independent reference implementation of the
// classic Poul-Henning Kamp md5crypt algorithm).
func TestMD5CryptKnownVectors(t *testing.T) {
	algo, err := Get("md5-crypt")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"mypassword", "$1$saltsalt$//251epTQaKpm7/bnAD.Z."},
		{"correct horse battery staple", "$1$abcdefgh$4/U5.w6NPtLkJ2WyrTwm91"},
		{"password123", "$1$12345678$tkslP1BQNfbrS2CGOUX.a."},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

func TestMD5CryptIsLegacyOnly(t *testing.T) {
	algo, err := Get("md5-crypt")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

// TestPhpassKnownVectors cross-validates against vectors generated with
// Python's passlib (github.com/glic3rinu/passlib successor,
// passlib.hash.phpass).
func TestPhpassKnownVectors(t *testing.T) {
	algo, err := Get("phpass")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"correct horse battery staple", "$P$616oJgEUyLNuWon9U5H4XwjiWXpPji/"},
		{"password123", "$P$8xlGKZ9Yi4zVwcnoxCvCD.X88JEFJY0"},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

// TestPhpassRejectsOutOfRangeCount checks that count_log2 values outside
// the reference implementation's 7..30 range are rejected instead of
// overflowing the iteration count.
func TestPhpassRejectsOutOfRangeCount(t *testing.T) {
	algo, err := Get("phpass")
	require.NoError(t, err)

	for _, countChar := range []string{".", "4", "T", "z"} {
		encoded := "$P$" + countChar + "12345678aaaaaaaaaaaaaaaaaaaaaa"
		_, err := algo.Decode(encoded)
		assert.Error(t, err, "count char %q", countChar)

		_, err = algo.Verify([]byte("pw"), encoded)
		assert.Error(t, err, "count char %q", countChar)
	}

	for _, countChar := range []string{"5", "S"} {
		_, err := algo.Decode("$P$" + countChar + "12345678aaaaaaaaaaaaaaaaaaaaaa")
		assert.NoError(t, err, "count char %q", countChar)
	}
}

func TestPhpassIsLegacyOnly(t *testing.T) {
	algo, err := Get("phpass")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

// TestSha256CryptKnownVectors cross-validates against the canonical test
// vectors published by Ulrich Drepper alongside the sha256-crypt/
// sha512-crypt specification (also reproduced by glibc's test-crypt.c and
// passlib's sha256_crypt tests).
func TestSha256CryptKnownVectors(t *testing.T) {
	algo, err := Get("sha256-crypt")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"},
		{"Hello world!", "$5$rounds=10000$saltstringsaltstring$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
		{"This is just a test", "$5$toolongsaltstring$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"},
		{
			"a very much longer text to encrypt.  This one even stretches over morethan one line.",
			"$5$rounds=1400$anotherlongsaltstring$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
		},
		{"we have a short salt string but not a short password", "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"},
		{"I like short passwords", "$5$rounds=123456$asalt$OmgQA6syAtYyL9TB/g7cAEq3YnRylFcPQGj5nJh9ez/"},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

func TestSha256CryptIsLegacyOnly(t *testing.T) {
	algo, err := Get("sha256-crypt")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

// TestSha512CryptKnownVectors cross-validates against the same reference
// test suite as TestSha256CryptKnownVectors.
func TestSha512CryptKnownVectors(t *testing.T) {
	algo, err := Get("sha512-crypt")
	require.NoError(t, err)

	cases := []struct {
		password string
		encoded  string
	}{
		{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{
			"Hello world!",
			"$6$rounds=10000$saltstringsaltstring$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
		},
		{"This is just a test", "$6$toolongsaltstring$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"},
		{
			"a very much longer text to encrypt.  This one even stretches over morethan one line.",
			"$6$rounds=1400$anotherlongsaltstring$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
		},
		{
			"we have a short salt string but not a short password",
			"$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
		},
		{
			"I like short passwords",
			"$6$rounds=123456$asalt$0sDmyBlWAiF6HZEv8Dd4N6d3KDaMxoYKfwGcCY8a26d2az3lfE.bXwTXlsFkreWksUapR/rDYV7rkJX.Xn.261",
		},
	}

	for _, c := range cases {
		assert.True(t, algo.Detect(c.encoded))

		ok, err := algo.Verify([]byte(c.password), c.encoded)
		require.NoError(t, err)
		assert.True(t, ok, "expected %q to verify against %q", c.password, c.encoded)

		ok, err = algo.Verify([]byte("wrong password"), c.encoded)
		require.NoError(t, err)
		assert.False(t, ok)
	}
}

func TestSha512CryptIsLegacyOnly(t *testing.T) {
	algo, err := Get("sha512-crypt")
	require.NoError(t, err)
	assert.True(t, algo.LegacyOnly())

	_, err = algo.Hash([]byte("pw"), Params{})
	assert.ErrorIs(t, err, ErrLegacyHashTarget)
}

func TestDetectAcrossAlgorithms(t *testing.T) {
	cases := map[string]string{
		"bcrypt":        "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga",
		"md5-crypt":     "$1$saltsalt$//251epTQaKpm7/bnAD.Z.",
		"phpass":        "$P$616oJgEUyLNuWon9U5H4XwjiWXpPji/",
		"pbkdf2-sha256": "$pbkdf2-sha256$i=600000$c2FsdHNhbHQ$aGFzaGhhc2g",
		"sha256-crypt":  "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		"sha512-crypt":  "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
	}
	for wantID, encoded := range cases {
		algo, err := Detect(encoded)
		require.NoError(t, err, "encoded=%s", encoded)
		assert.Equal(t, wantID, algo.ID(), "encoded=%s", encoded)
	}
}
