# Pashly

Pashly generates passwords, hashes them with configurable parameters, and
verifies passwords against hashes — built to support IAM/CIAM migration
work (moving user stores between systems like Auth0, Okta, Keycloak,
Django, WordPress, ASP.NET Identity, and Duende IdentityServer).

## Installation

```sh
go install github.com/cerberauth/pashly@latest
```

Pre-built binaries, Docker images, and platform packages (deb/rpm/apk,
Homebrew, Scoop, AUR, winget, Chocolatey, Snap) are published on each
[release](https://github.com/cerberauth/pashly/releases).

## Commands

### `pashly generate` — generate random passwords

```sh
# One password, 20 characters, letters+digits+symbols (defaults)
pashly generate

# Five 32-character alphanumeric-only passwords
pashly generate -n 5 -l 32 --charset alnum

# Exclude visually ambiguous characters (il1Lo0O), machine-readable output
pashly generate -l 24 --no-ambiguous --format json

# A custom character set
pashly generate --charset 'custom:ABCDEF0123456789' -l 16
```

### `pashly hash` — hash a password

```sh
# Argon2id with current OWASP-recommended defaults (the tool's own default algorithm)
pashly hash --stdin
# (prompts securely if stdin is a terminal, or reads a piped password)

# bcrypt, explicit cost
echo -n 'correct horse battery staple' | pashly hash --stdin -a bcrypt --cost 12

# scrypt, pbkdf2 variants
pashly hash --password-file ./pw.txt -a scrypt --iterations 17   # N = 2^17
pashly hash --password-file ./pw.txt -a pbkdf2-sha256 --iterations 600000
```

`--password` is accepted for convenience but warns on stderr — prefer
`--stdin` or `--password-file` so the plaintext never appears in shell
history or `ps` output.

#### Migration-flavored: hashing for a specific platform's bulk import

```sh
# Hash for Auth0's bulk user import (custom_password_hash / bcrypt)
pashly hash --stdin --target auth0 > auth0-custom-password-hash.json

# Hash for Okta's Import Hashed Password API (bcrypt)
pashly hash --stdin --target okta

# Hash for a Keycloak realm import (pbkdf2-sha256, CredentialRepresentation)
pashly hash --stdin --target keycloak > keycloak-credential.json

# Hash for a Django user fixture (PBKDF2PasswordHasher)
pashly hash --stdin --target django

# Hash for WordPress 6.8+ ($wp$ bcrypt over an HMAC-SHA384 pre-hash)
pashly hash --stdin --target wordpress

# Hash for an ASP.NET Core Identity v3 user store (PBKDF2-HMAC-SHA512)
pashly hash --stdin --target aspnet-identity
```

`--target` selects the platform's algorithm and current recommended
parameters automatically; it cannot be combined with `-a/--algorithm`.
Tuning flags (`--cost`, `--iterations`, ...) still work under `--target`
to override that platform's defaults.

### `pashly verify` — verify a password against a hash

```sh
pashly verify --hash '$argon2id$v=19$m=19456,t=2,p=1$...' --stdin
pashly verify --hash-file ./user.hash --password-file ./attempt.txt
```

Exit codes are scriptable: `0` = match, `1` = no match, `2` = error (bad
input, unparsable hash). Algorithm/target auto-detection covers pashly's
own canonical formats, bcrypt, legacy md5-crypt/sha256-crypt/sha512-crypt/
phpass, and every `--target` platform's native encoding; override with
`--algorithm` (an algorithm ID like `bcrypt`, or a target name like
`auth0`) if needed.

#### Migration-flavored: verifying an exported hash during a cutover

```sh
# Verify a login attempt against a hash exported from Auth0's bulk export
pashly verify --hash-file ./exported-auth0-hash.json --stdin
echo "exit=$?"   # use in a CI/cutover script to gate on real user data

# Verify against a Django-formatted hash pulled from a database dump
pashly verify --hash 'pbkdf2_sha256$720000$...$...' --password-file ./attempt.txt

# Force interpretation as a specific legacy format during a phpBB/Drupal 7 migration
pashly verify --hash '$P$...' --algorithm phpass --stdin
```

### `pashly info` — inspect a hash

```sh
pashly info '$argon2id$v=19$m=19456,t=2,p=1$VEL4z...$80p0w...'
pashly info --format json "$(cat ./user.hash)"
```

Prints the detected (or `--algorithm`-forced) algorithm, its string
encoding, and its parameters — useful when auditing what an exported user
store is actually using before planning a migration.

## Supported algorithms

| ID | Hash target? | Verify/info? | Notes |
|---|---|---|---|
| `argon2id` | yes (default) | yes | OWASP-recommended default; PHC string format |
| `argon2i` | yes | yes | PHC string format |
| `bcrypt` | yes | yes | native `$2a$/$2b$/$2y$` encoding |
| `scrypt` | yes | yes | pashly's own PHC-style convention (`ln=`) |
| `pbkdf2-sha256` | yes | yes | PHC-style, passlib convention |
| `pbkdf2-sha512` | yes | yes | PHC-style, passlib convention |
| `pbkdf2-sha1` | yes | yes | legacy interop only; never the default |
| `md5-crypt` | no | yes | legacy (`$1$`); verify/info only |
| `sha256-crypt` | no | yes | legacy (`$5$`); verify/info only |
| `sha512-crypt` | no | yes | legacy (`$6$`); verify/info only |
| `phpass` | no | yes | legacy (`$P$`/`$H$`); verify/info only |

## `--target` platforms

`auth0`, `okta`, `keycloak`, `django`, `wordpress`, `aspnet-identity`.

## Security notes

- Passwords are never logged, at any verbosity level.
- `verify` uses a constant-time comparison of the derived key.
- Default parameters follow the current OWASP Password Storage Cheat
  Sheet.
- Legacy formats (`md5-crypt`, `sha256-crypt`, `sha512-crypt`, `phpass`,
  `pbkdf2-sha1`) exist for migrating *away from* older systems — pashly
  will never produce them as a `hash` target.

## Telemetry

The CLI collects anonymous usage data to help improve the tool: which command ran, the names (never the values) of the flags used, how the command exited and how long it took, the CLI version, OS and architecture, and basic resource usage, how often a command was mistyped (never what you typed), whether it crashed (never the crash message), plus a few counts and timings that never contain your input: how long hashing took by algorithm and `--target` platform, which algorithm and platform format `info` and `verify` worked out (and whether `--algorithm` forced it), and whether `verify` matched, and how `generate` was used: the charset preset (a custom charset is reported as `custom`, never its characters), the output format, the requested length and count. Interactive runs also include a random install and session identifier, the shell and terminal emulator you run it in (from a fixed list) and whether its output is piped; runs in CI are fully anonymous. Passwords, hashes, salts and parameters are never collected. You can opt out of telemetry by passing the `--sqa-opt-out` flag, or by setting `DO_NOT_TRACK=1` (or `ARGVIO_DISABLED=1`).

## Development

```sh
go build ./...
go test ./...
```

## License

MIT — see [LICENSE](LICENSE).
