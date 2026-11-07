package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/cerberauth/pashly/internal/hash"
	"github.com/cerberauth/pashly/internal/target"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
)

// resolvedHash carries everything verify/info need regardless of whether
// the encoded string was pashly's own canonical format or a --target
// platform's native representation.
type resolvedHash struct {
	label  string // algorithm ID, or "target:<name>" for target formats
	result hash.Result
	algo   hash.Algorithm

	// canonical is the string to hand to algo.Verify. For a directly
	// detected/forced algorithm it's the original input, already in that
	// algorithm's own format. For a --target format it's re-encoded from
	// result into the underlying algorithm's canonical form, since the
	// target's native string isn't understood by algo.Verify.
	canonical string
}

func (r resolvedHash) verify(password []byte) (bool, error) {
	return r.algo.Verify(password, r.canonical)
}

// resolveHash detects (or, if override is non-empty, forces) the
// algorithm/target an encoded hash was produced with. override may be
// either a hash.Algorithm ID (bcrypt, argon2id, ...) or a --target name
// (auth0, okta, ...).
func resolveHash(encoded, override string) (resolvedHash, error) {
	if override != "" {
		if algo, err := hash.Get(override); err == nil {
			result, err := algo.Decode(encoded)
			if err != nil {
				return resolvedHash{}, fmt.Errorf("decoding as %s: %w", override, err)
			}
			return resolvedHash{label: override, result: result, algo: algo, canonical: encoded}, nil
		}
		if adapter, err := target.Get(override); err == nil {
			return resolveViaTarget(adapter, encoded)
		}
		return resolvedHash{}, fmt.Errorf("unknown algorithm or target %q", override)
	}

	if algo, err := hash.Detect(encoded); err == nil {
		result, err := algo.Decode(encoded)
		if err != nil {
			return resolvedHash{}, err
		}
		return resolvedHash{label: algo.ID(), result: result, algo: algo, canonical: encoded}, nil
	}

	if adapter := sniffTarget(encoded); adapter != nil {
		return resolveViaTarget(adapter, encoded)
	}

	return resolvedHash{}, fmt.Errorf("unable to detect algorithm or target for the given hash; use --algorithm to specify one explicitly")
}

func resolveViaTarget(adapter target.Adapter, encoded string) (resolvedHash, error) {
	result, err := adapter.Decode(encoded)
	if err != nil {
		return resolvedHash{}, fmt.Errorf("decoding as %s: %w", adapter.Name(), err)
	}
	algo, err := hash.Get(adapter.AlgorithmID())
	if err != nil {
		return resolvedHash{}, err
	}
	canonical, err := algo.Encode(result)
	if err != nil {
		return resolvedHash{}, err
	}
	return resolvedHash{label: "target:" + adapter.Name(), result: result, algo: algo, canonical: canonical}, nil
}

// sniffTarget makes a best-effort guess at which --target format encoded
// is, based on its shape, trying each candidate's real Decode as the
// final check. Used only when hash.Detect (pashly's own canonical/legacy
// formats) fails to match, since target formats are platform-specific and
// not otherwise auto-detectable with full confidence.
func sniffTarget(encoded string) target.Adapter {
	trimmed := strings.TrimSpace(encoded)

	var candidates []string
	switch {
	case strings.HasPrefix(trimmed, "$wp$"):
		candidates = []string{"wordpress"}
	case strings.HasPrefix(trimmed, "pbkdf2_sha256$"):
		candidates = []string{"django"}
	case strings.HasPrefix(trimmed, "{"):
		candidates = []string{"auth0", "okta", "keycloak"}
	default:
		candidates = []string{"aspnet-identity"}
	}

	for _, name := range candidates {
		adapter, err := target.Get(name)
		if err != nil {
			continue
		}
		if _, err := adapter.Decode(trimmed); err == nil {
			return adapter
		}
	}
	return nil
}

// Hash metrics, declared in the Argvio catalog. Algorithms and targets come
// from pashly's own registries, never from the hash or password.
var (
	hashDuration      = argvio.NewDuration("hash.run", argvio.Dims("algorithm", "target"))
	resolvedCounter   = argvio.NewCounter("hash.resolved", argvio.Dims("algorithm", "target", "detection"))
	verifyResultCount = argvio.NewCounter("verify.result", argvio.Dims("algorithm", "result"))
)

func algorithmLabel(id string) string { return telemetryx.Vocab(id, hash.IDs()...) }

// targetLabel is the --target platform name, or "none".
func targetLabel(name string) string {
	if name == "" {
		return "none"
	}
	return telemetryx.Vocab(name, target.Names()...)
}

// recordResolved counts a hash info or verify worked out: its algorithm, the
// platform format it was in ("none" for pashly's own) and whether the user
// forced it or it was detected.
func recordResolved(ctx context.Context, r resolvedHash, override string) {
	detection := "detected"
	if override != "" {
		detection = "forced"
	}
	platform := ""
	if name, ok := strings.CutPrefix(r.label, "target:"); ok {
		platform = name
	}
	resolvedCounter.Add(ctx, 1, algorithmLabel(r.algo.ID()), targetLabel(platform), detection)
}

// recordVerify counts a verify outcome: "match" or "no-match".
func recordVerify(ctx context.Context, r resolvedHash, matched bool) {
	result := "no-match"
	if matched {
		result = "match"
	}
	verifyResultCount.Add(ctx, 1, algorithmLabel(r.algo.ID()), result)
}
