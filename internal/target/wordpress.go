package target

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
)

// wordpressAdapter implements WordPress's current (6.8+) password format:
// a bcrypt hash using the $2y$ prefix (PHP's PASSWORD_BCRYPT convention) of
// the password pre-hashed with HMAC-SHA384, wrapped with a literal "$wp"
// prefix to signal to older WordPress code paths that this is not a plain
// bcrypt or legacy phpass hash. Reference: WordPress core
// wp_hash_password()/wp_check_password() in wp-includes/pluggable.php.
//
// Legacy phpass ($P$/$H$) hashes are supported for verify/info only, via
// the "phpass" algorithm in internal/hash — never as a hash target.
type wordpressAdapter struct{}

func (wordpressAdapter) Name() string        { return NameWordpress }
func (wordpressAdapter) AlgorithmID() string { return hash.IDBcrypt }

const wordpressDefaultCost = 12

func (wordpressAdapter) DefaultParams() hash.Params {
	return hash.Params{Cost: wordpressDefaultCost}
}

// wordpressHMACKey is the HMAC key WordPress uses for domain separation.
const wordpressHMACKey = "wp-sha384"

// PreparePassword reproduces WordPress 6.8+'s pre-hash:
// base64_encode(hash_hmac('sha384', $password, 'wp-sha384', true)).
func (wordpressAdapter) PreparePassword(password []byte) []byte {
	mac := hmac.New(sha512.New384, []byte(wordpressHMACKey))
	mac.Write(password)
	sum := mac.Sum(nil)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(out, sum)
	return out
}

// Hash trims the password before pre-hashing it, as wp_hash_password does
// (wp_check_password does not trim, hence PreparePassword doesn't).
func (w wordpressAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(w.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Cost == 0 {
		params.Cost = wordpressDefaultCost
	}
	return algo.Hash(w.PreparePassword(bytes.TrimSpace(password)), params)
}

func (w wordpressAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != w.AlgorithmID() {
		return "", fmt.Errorf("wordpress target requires a bcrypt hash.Result, got %q", r.Algorithm)
	}
	bcryptStr := string(r.Key)
	if len(bcryptStr) < 4 {
		return "", fmt.Errorf("invalid bcrypt hash")
	}
	// Rewrite the $2a$/$2b$ minor version to $2y$, PHP's PASSWORD_BCRYPT
	// convention, then wrap with WordPress's own "$wp" prefix (the "$2y$"
	// that follows already supplies the separating '$').
	wpBcrypt := "$2y$" + bcryptStr[4:]
	return "$wp" + wpBcrypt, nil
}

func (w wordpressAdapter) Decode(encoded string) (hash.Result, error) {
	rest, ok := strings.CutPrefix(encoded, "$wp")
	if !ok {
		return hash.Result{}, fmt.Errorf("not a valid WordPress $wp$ bcrypt hash")
	}
	algo, err := hash.Get("bcrypt")
	if err != nil {
		return hash.Result{}, err
	}
	return algo.Decode(rest)
}
