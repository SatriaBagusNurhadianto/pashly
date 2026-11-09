// Package target implements pashly's --target format adapters: one file
// per IAM/CIAM platform, isolating that platform's encoding quirks.
package target

import (
	"fmt"

	"github.com/cerberauth/pashly/internal/hash"
)

// Adapter converts pashly's canonical hash.Result into (or reads from) a
// specific platform's on-disk/API representation.
type Adapter interface {
	// Name returns the --target identifier (e.g. "auth0").
	Name() string

	// AlgorithmID returns the pashly algorithm this platform expects.
	AlgorithmID() string

	// DefaultParams returns this platform's current recommended
	// parameters, used when the user supplies no tuning flags.
	DefaultParams() hash.Params

	// PreparePassword transforms the password the way this platform does
	// before handing it to the underlying algorithm (e.g. WordPress 6.8+'s
	// HMAC-SHA384 pre-hash). Hash applies it itself; verify must apply it
	// before calling the underlying algorithm's Verify.
	PreparePassword(password []byte) []byte

	// Hash derives a canonical hash.Result for this platform. Most
	// adapters delegate straight to the underlying hash.Algorithm; some
	// (e.g. django) need target-specific salt formatting and so own their
	// derivation instead of merely re-encoding a generic Result.
	Hash(password []byte, params hash.Params) (hash.Result, error)

	// Encode converts a canonical hash.Result into this platform's native
	// string/JSON representation.
	Encode(hash.Result) (string, error)

	// Decode parses this platform's native representation back into a
	// canonical hash.Result, for verify/info to operate on.
	Decode(string) (hash.Result, error)
}

// rawPassword is embedded by adapters whose platform hashes the password
// as-is.
type rawPassword struct{}

func (rawPassword) PreparePassword(password []byte) []byte { return password }

// --target identifiers, one per supported platform.
const (
	NameAuth0          = "auth0"
	NameOkta           = "okta"
	NameKeycloak       = "keycloak"
	NameDjango         = "django"
	NameWordpress      = "wordpress"
	NameASPNetIdentity = "aspnet-identity"
)

var registry = map[string]Adapter{
	NameAuth0:          auth0Adapter{},
	NameOkta:           oktaAdapter{},
	NameKeycloak:       keycloakAdapter{},
	NameDjango:         djangoAdapter{},
	NameWordpress:      wordpressAdapter{},
	NameASPNetIdentity: aspnetIdentityAdapter{},
}

// Names returns every registered --target identifier, in a stable order
// suitable for --help text.
func Names() []string {
	return []string{NameAuth0, NameOkta, NameKeycloak, NameDjango, NameWordpress, NameASPNetIdentity}
}

// Get returns the Adapter registered under name.
func Get(name string) (Adapter, error) {
	a, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown target %q", name)
	}
	return a, nil
}
