package target

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
)

// oktaAdapter implements Okta's "Import Hashed Password" bcrypt schema.
// v1 ships bcrypt only; Okta's PBKDF2-SHA256 import variant is deferred
// to keep the adapter surface small.
// Reference: Okta Import Hashed Password.
type oktaAdapter struct{ rawPassword }

func (oktaAdapter) Name() string        { return NameOkta }
func (oktaAdapter) AlgorithmID() string { return hash.IDBcrypt }

const oktaDefaultCost = 10

func (oktaAdapter) DefaultParams() hash.Params {
	return hash.Params{Cost: oktaDefaultCost}
}

func (o oktaAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(o.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Cost == 0 {
		params.Cost = oktaDefaultCost
	}
	return algo.Hash(password, params)
}

// oktaAlgorithmBcrypt is the credentials.password.hash.algorithm value for
// bcrypt imports. saltOrder only applies to Okta's SHA-* and MD5 imports, so
// it is neither emitted nor checked here.
const oktaAlgorithmBcrypt = "BCRYPT"

type oktaImportHashedPassword struct {
	Algorithm  string `json:"algorithm"`
	WorkFactor int    `json:"workFactor"`
	Salt       string `json:"salt"`
	Value      string `json:"value"`
}

func (o oktaAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != o.AlgorithmID() {
		return "", fmt.Errorf("okta target requires a bcrypt hash.Result, got %q", r.Algorithm)
	}
	salt, hashPart, cost, ok := hash.BcryptSplitSaltHash(string(r.Key))
	if !ok {
		return "", fmt.Errorf("unable to split bcrypt hash for okta encoding")
	}
	out := oktaImportHashedPassword{
		Algorithm:  oktaAlgorithmBcrypt,
		WorkFactor: cost,
		Salt:       salt,
		Value:      hashPart,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (o oktaAdapter) Decode(encoded string) (hash.Result, error) {
	var in oktaImportHashedPassword
	if err := json.Unmarshal([]byte(encoded), &in); err != nil {
		return hash.Result{}, fmt.Errorf("parsing okta ImportHashedPassword JSON: %w", err)
	}
	if !strings.EqualFold(in.Algorithm, oktaAlgorithmBcrypt) {
		return hash.Result{}, fmt.Errorf("unsupported okta algorithm %q (only BCRYPT is supported)", in.Algorithm)
	}
	full := hash.BcryptJoinSaltHash(in.Salt, in.Value, in.WorkFactor)
	algo, err := hash.Get("bcrypt")
	if err != nil {
		return hash.Result{}, err
	}
	return algo.Decode(full)
}
