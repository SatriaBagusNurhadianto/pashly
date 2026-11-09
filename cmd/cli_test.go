package cmd_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binPath is built once in TestMain and exercised as a real subprocess,
// exactly as a user would invoke pashly — this avoids cross-test
// contamination from cobra's package-level flag variables, which would
// otherwise leak state between in-process Execute() calls.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pashly-cli-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binPath = filepath.Join(dir, "pashly")
	build := exec.Command("go", "build", "-o", binPath, "..")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"--sqa-opt-out"}, args...)...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("running pashly: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestGeneratePlain(t *testing.T) {
	stdout, _, code := run(t, "generate", "-n", "3", "-l", "16")
	require.Equal(t, 0, code)
	lines := splitNonEmptyLines(stdout)
	assert.Len(t, lines, 3)
	for _, l := range lines {
		assert.Len(t, l, 16)
	}
}

func TestGenerateCustomCharset(t *testing.T) {
	stdout, _, code := run(t, "generate", "-l", "10", "--charset", `custom:ab`)
	require.Equal(t, 0, code)
	pw := splitNonEmptyLines(stdout)[0]
	for _, r := range pw {
		assert.Contains(t, "ab", string(r))
	}
}

func TestHashAndVerifyRoundtrip(t *testing.T) {
	hashOut, _, code := run(t, "hash", "--password", "correct horse battery staple", "-a", "argon2id")
	require.Equal(t, 0, code)
	encoded := splitNonEmptyLines(hashOut)[0]
	assert.Contains(t, encoded, "$argon2id$")

	_, _, code = run(t, "verify", "--hash", encoded, "--password", "correct horse battery staple")
	assert.Equal(t, 0, code)

	_, _, code = run(t, "verify", "--hash", encoded, "--password", "wrong password")
	assert.Equal(t, 1, code)
}

func TestVerifyErrorExitCode(t *testing.T) {
	_, stderr, code := run(t, "verify", "--hash", "not a valid hash", "--password", "x")
	assert.Equal(t, 2, code)
	assert.NotEmpty(t, stderr)
}

func TestHashTargetMutuallyExclusiveWithAlgorithm(t *testing.T) {
	_, stderr, code := run(t, "hash", "--password", "x", "-a", "bcrypt", "--target", "auth0")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "mutually exclusive")
}

func TestHashTargetDjangoRoundtripsThroughVerify(t *testing.T) {
	hashOut, _, code := run(t, "hash", "--password", "correct horse battery staple", "--target", "django", "--iterations", "1000")
	require.Equal(t, 0, code)
	encoded := splitNonEmptyLines(hashOut)[0]
	assert.Regexp(t, `^pbkdf2_sha256\$1000\$`, encoded)

	_, _, code = run(t, "verify", "--hash", encoded, "--password", "correct horse battery staple")
	assert.Equal(t, 0, code)
}

func TestVerifyAgainstTargetEncodedHash(t *testing.T) {
	for _, tc := range []struct {
		target string
		args   []string
	}{
		{"django", []string{"--iterations", "1000"}},
		{"auth0", []string{"--cost", "4"}},
		{"wordpress", []string{"--cost", "4"}},
	} {
		t.Run(tc.target, func(t *testing.T) {
			args := append([]string{"hash", "--password", "correct horse battery staple", "--target", tc.target}, tc.args...)
			hashOut, _, code := run(t, args...)
			require.Equal(t, 0, code)
			encoded := strings.TrimSpace(hashOut) // may be multi-line JSON (auth0/okta/keycloak)

			_, _, code = run(t, "verify", "--hash", encoded, "--password", "correct horse battery staple")
			assert.Equal(t, 0, code)

			_, _, code = run(t, "verify", "--hash", encoded, "--password", "wrong password")
			assert.Equal(t, 1, code)

			infoOut, _, code := run(t, "info", encoded)
			require.Equal(t, 0, code)
			assert.Contains(t, infoOut, "target:"+tc.target)
		})
	}
}

func TestInfoDetectsBcrypt(t *testing.T) {
	hashOut, _, code := run(t, "hash", "--password", "x", "-a", "bcrypt", "--cost", "4")
	require.Equal(t, 0, code)
	encoded := splitNonEmptyLines(hashOut)[0]

	infoOut, _, code := run(t, "info", encoded)
	require.Equal(t, 0, code)
	assert.Contains(t, infoOut, "algorithm: bcrypt")
	assert.Contains(t, infoOut, "cost: 4")
}

func TestVerifyLegacyFormats(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hash     string
		password string
	}{
		{"md5-crypt", "$1$saltsalt$//251epTQaKpm7/bnAD.Z.", "mypassword"},
		{"phpass", "$P$616oJgEUyLNuWon9U5H4XwjiWXpPji/", "correct horse battery staple"},
		{"sha256-crypt", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"},
		{
			"sha512-crypt",
			"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
			"Hello world!",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, code := run(t, "verify", "--hash", tc.hash, "--password", tc.password)
			assert.Equal(t, 0, code)

			_, _, code = run(t, "verify", "--hash", tc.hash, "--password", "wrong password")
			assert.Equal(t, 1, code)

			infoOut, _, code := run(t, "info", tc.hash)
			require.Equal(t, 0, code)
			assert.Contains(t, infoOut, "algorithm: "+tc.name)
			assert.Contains(t, infoOut, "legacy")
		})
	}
}

func TestHashRejectsLegacyAlgorithms(t *testing.T) {
	for _, id := range []string{"md5-crypt", "phpass", "sha256-crypt", "sha512-crypt"} {
		t.Run(id, func(t *testing.T) {
			_, stderr, code := run(t, "hash", "--password", "x", "-a", id)
			assert.Equal(t, 2, code)
			assert.Contains(t, stderr, "verify/info only")
		})
	}
}

func TestPasswordInputMutualExclusivity(t *testing.T) {
	_, stderr, code := run(t, "hash", "--password", "x", "--stdin")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "mutually exclusive")
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestVerifyWordpress68Hash(t *testing.T) {
	// Produced by WordPress 6.8's wp_hash_password() code path (PHP 8.3).
	const encoded = "$wp$2y$04$CJbTd7D7r3NEIEQhv9x0zuuZ.dw.4ZT4whKecDlb0xsd8KKVydw2K"

	_, stderr, code := run(t, "verify", "--hash", encoded, "--password", "correct horse battery staple")
	assert.Equal(t, 0, code, stderr)

	_, _, code = run(t, "verify", "--hash", encoded, "--password", "wrong")
	assert.Equal(t, 1, code)
}

func TestVerifyMalformedArgon2ExitsWithError(t *testing.T) {
	for _, encoded := range []string{
		"$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
	} {
		_, stderr, code := run(t, "verify", "--hash", encoded, "--password", "x")
		assert.Equal(t, 2, code, stderr)
		assert.NotContains(t, stderr, "panic")
	}
}
