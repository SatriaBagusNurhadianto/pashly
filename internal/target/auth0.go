package target

import (
	"encoding/json"
	"fmt"

	"github.com/cerberauth/pashly/internal/hash"
)

// auth0Adapter implements Auth0's bulk user import "custom_password_hash"
// schema for bcrypt. Reference: Auth0 bulk import users – custom password
// hash.
type auth0Adapter struct{ rawPassword }

func (auth0Adapter) Name() string        { return NameAuth0 }
func (auth0Adapter) AlgorithmID() string { return hash.IDBcrypt }

// auth0DefaultCost matches the cost Auth0's own dashboard uses for
// bcrypt-hashed passwords.
const auth0DefaultCost = 10

func (auth0Adapter) DefaultParams() hash.Params {
	return hash.Params{Cost: auth0DefaultCost}
}

func (a auth0Adapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(a.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Cost == 0 {
		params.Cost = auth0DefaultCost
	}
	return algo.Hash(password, params)
}

type auth0CustomPasswordHash struct {
	Algorithm string       `json:"algorithm"`
	Hash      auth0HashVal `json:"hash"`
}

type auth0HashVal struct {
	Value    string `json:"value"`
	Encoding string `json:"encoding"`
}

func (a auth0Adapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != a.AlgorithmID() {
		return "", fmt.Errorf("auth0 target requires a bcrypt hash.Result, got %q", r.Algorithm)
	}
	out := auth0CustomPasswordHash{
		Algorithm: "bcrypt",
		Hash: auth0HashVal{
			Value:    string(r.Key),
			Encoding: "utf8",
		},
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (a auth0Adapter) Decode(encoded string) (hash.Result, error) {
	var in auth0CustomPasswordHash
	if err := json.Unmarshal([]byte(encoded), &in); err != nil {
		return hash.Result{}, fmt.Errorf("parsing auth0 custom_password_hash JSON: %w", err)
	}
	if in.Algorithm != "bcrypt" {
		return hash.Result{}, fmt.Errorf("unsupported auth0 hash algorithm %q (only bcrypt is supported)", in.Algorithm)
	}
	algo, err := hash.Get("bcrypt")
	if err != nil {
		return hash.Result{}, err
	}
	return algo.Decode(in.Hash.Value)
}
