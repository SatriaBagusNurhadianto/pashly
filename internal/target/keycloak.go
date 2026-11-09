package target

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cerberauth/pashly/internal/hash"
)

// keycloakAdapter implements Keycloak's user export credential schema for
// its default PBKDF2-SHA256 hasher (since Keycloak 8.0). Reference:
// Keycloak Server Admin Guide – Password hashing.
type keycloakAdapter struct{ rawPassword }

func (keycloakAdapter) Name() string        { return NameKeycloak }
func (keycloakAdapter) AlgorithmID() string { return hash.IDPbkdf2Sha256 }

// keycloakDefaultIterations matches Keycloak's own current default
// hashIterations for the pbkdf2-sha256 provider.
const keycloakDefaultIterations = 27500

func (keycloakAdapter) DefaultParams() hash.Params {
	return hash.Params{Iterations: keycloakDefaultIterations, SaltLength: 16, KeyLength: 32}
}

func (k keycloakAdapter) Hash(password []byte, params hash.Params) (hash.Result, error) {
	algo, err := hash.Get(k.AlgorithmID())
	if err != nil {
		return hash.Result{}, err
	}
	if params.Iterations == 0 {
		params.Iterations = keycloakDefaultIterations
	}
	return algo.Hash(password, params)
}

// keycloakCredential mirrors Keycloak's realm-export CredentialRepresentation,
// where credentialData and secretData are themselves JSON-encoded strings.
type keycloakCredential struct {
	Type           string `json:"type"`
	CredentialData string `json:"credentialData"`
	SecretData     string `json:"secretData"`
}

type keycloakCredentialData struct {
	HashIterations int    `json:"hashIterations"`
	Algorithm      string `json:"algorithm"`
}

type keycloakSecretData struct {
	Value string `json:"value"`
	Salt  string `json:"salt"`
}

func (k keycloakAdapter) Encode(r hash.Result) (string, error) {
	if r.Algorithm != k.AlgorithmID() {
		return "", fmt.Errorf("keycloak target requires a pbkdf2-sha256 hash.Result, got %q", r.Algorithm)
	}
	credData, err := json.Marshal(keycloakCredentialData{
		HashIterations: r.Params.Iterations,
		Algorithm:      "pbkdf2-sha256",
	})
	if err != nil {
		return "", err
	}
	secretData, err := json.Marshal(keycloakSecretData{
		Value: base64.StdEncoding.EncodeToString(r.Key),
		Salt:  base64.StdEncoding.EncodeToString(r.Salt),
	})
	if err != nil {
		return "", err
	}
	out := keycloakCredential{
		Type:           "password",
		CredentialData: string(credData),
		SecretData:     string(secretData),
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (k keycloakAdapter) Decode(encoded string) (hash.Result, error) {
	var cred keycloakCredential
	if err := json.Unmarshal([]byte(encoded), &cred); err != nil {
		return hash.Result{}, fmt.Errorf("parsing keycloak CredentialRepresentation JSON: %w", err)
	}
	var credData keycloakCredentialData
	if err := json.Unmarshal([]byte(cred.CredentialData), &credData); err != nil {
		return hash.Result{}, fmt.Errorf("parsing keycloak credentialData JSON: %w", err)
	}
	if credData.Algorithm != "pbkdf2-sha256" {
		return hash.Result{}, fmt.Errorf("unsupported keycloak algorithm %q (only pbkdf2-sha256 is supported)", credData.Algorithm)
	}
	var secretData keycloakSecretData
	if err := json.Unmarshal([]byte(cred.SecretData), &secretData); err != nil {
		return hash.Result{}, fmt.Errorf("parsing keycloak secretData JSON: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(secretData.Salt)
	if err != nil {
		return hash.Result{}, fmt.Errorf("decoding keycloak salt: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(secretData.Value)
	if err != nil {
		return hash.Result{}, fmt.Errorf("decoding keycloak hash value: %w", err)
	}
	return hash.Result{
		Algorithm: k.AlgorithmID(),
		Params:    hash.Params{Iterations: credData.HashIterations, SaltLength: len(salt), KeyLength: len(key)},
		Salt:      salt,
		Key:       key,
	}, nil
}
