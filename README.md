# uniform-passwords

Password generator using exact uniform sampling across every password that
satisfies selected character-class constraints. It performs no file, clipboard, network,
telemetry, deterministic-seed, or batch-uniqueness operations.

Source repository: <https://github.com/otrumb/uniform-passwords>. No PyPI package,
tag, release, or package publication exists.

## Usage

```console
uniform-passwords
uniform-passwords --length 32 --count 5 --no-ambiguous
uniform-passwords --no-symbols --exclude abc --exclude XYZ
uniform-passwords --json
python -m uniform_passwords --no-symbols
```

Plain output contains exactly one generated password per line. `--json` emits policy,
exact valid-space size, entropy (`log2` of that space), and generated passwords. Each
password is an independent draw, so duplicates are allowed.

## Options and fixed alphabets

| Option | Default | Meaning |
| --- | --- | --- |
| `-h`, `--help` | not set | Show help and exit. |
| `--length INTEGER` | `20` | Password length, from 1 through 1024. |
| `--count INTEGER` | `1` | Independent draws, from 1 through 1000. |
| `--lowercase`, `--no-lowercase` | enabled | Include or disable lowercase and require at least one when enabled. |
| `--uppercase`, `--no-uppercase` | enabled | Include or disable uppercase and require at least one when enabled. |
| `--digits`, `--no-digits` | enabled | Include or disable digits and require at least one when enabled. |
| `--symbols`, `--no-symbols` | enabled | Include or disable symbols and require at least one when enabled. |
| `--ambiguous`, `--no-ambiguous` | enabled | Keep or remove visually ambiguous characters. |
| `--exclude TEXT` | none | Remove printable ASCII characters; repeatable and cumulative. |
| `--json` | not set | Emit one pretty JSON document instead of password-only lines. |

Class alphabets are fixed:

- Lowercase: `abcdefghijklmnopqrstuvwxyz`
- Uppercase: `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
- Digits: `0123456789`
- Symbols: `!@#$%^&*()-_=+[]{};:,.?/`
- Ambiguous set: `IlL1O0o|`; `--no-ambiguous` removes exactly these characters wherever present.

At least one class must remain enabled. Exclusions and ambiguity removal apply to every
enabled class and must not empty one. Each generated password contains at least one
character from every enabled class, and length must accommodate class count. `length *
count` must not exceed 1,000,000 characters. Option abbreviations are rejected.

## JSON schema

`valid_space` is a decimal string so arbitrarily large exact counts survive JSON number
limits. `entropy_bits` is rounded to two decimal places. Password array values below are
placeholders, not generated or usable credentials.

```json
{
  "schema_version": "uniform-passwords/v1",
  "policy": {
    "length": 20,
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": true,
    "ambiguous": true,
    "exclude": []
  },
  "valid_space": "<exact-decimal-count>",
  "entropy_bits": 0.0,
  "passwords": ["<generated-value>"]
}
```

Batch draws are independent with replacement. Duplicate passwords are valid; no uniqueness
tracking or retry occurs.

## Security and exposure

Random ranks come from Python's `secrets` module and map exactly to valid passwords
without modulo bias, rejection sampling, or forced class placement. Reported entropy is
`log2` of exact count of valid passwords for one draw under selected policy. It is not
total batch entropy and not a claim about strength of a password chosen, reused, memorized,
modified, or exposed by a user.

Generated passwords can remain visible in terminal scrollback. Pipes, redirection, and
command substitution expose output to receiving processes, shell behavior, and stored
files. Values passed to `--exclude` may be recorded in shell history. Avoid putting
existing secrets in exclusions.

NIST guidance generally treats composition rules as verifier guidance rather than a
universal recipe for stronger user-chosen passwords. This tool's class guarantees exist
for compatibility with verifiers that require such rules; they do not replace NIST's
guidance for verifier design, blocklists, rate limiting, secure storage, or MFA.

The tool has no storage, network, clipboard, deterministic seed, or unique-batch feature.
Never publish generated values or artifacts containing them.

## Development

```console
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run basedpyright
uv run pytest
uv run python -m compileall -q src tests
uv run python -m build
```
