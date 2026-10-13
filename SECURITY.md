# Security

`uniform-passwords` creates values locally and writes them only to standard output. It performs no storage, network, telemetry, clipboard, deterministic-seed, or batch-uniqueness operation.

Generated output is sensitive. Terminal scrollback, screen capture, process observation, pipes, redirection, command substitution, logs, and shell history can expose it. Values supplied to `--exclude` may also enter shell history; never pass an existing secret there.

Random ranks come from Python's `secrets.randbelow`. Exact dynamic-programming counts and unranking map each rank uniformly to one password satisfying the selected policy. Security still depends on protecting output and avoiding reuse or user modification.

After source publication, report suspected vulnerabilities through GitHub private vulnerability reporting at <https://github.com/otrumb/uniform-passwords/security/advisories/new>. Until publication, report privately to the maintainer. Include version, OS, command, expected result, and observed result. Never include real credentials or generated values.
