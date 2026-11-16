# cs-ci-secretscan

**A case study: using Vornik to build and operate CI secret scanning.**
`secretscan` runs a repository's secret scan in four layers around
[gitleaks](https://github.com/gitleaks/gitleaks): deterministic checks that
can fail and counts that must balance, plus an optional model review that
may only comment.

## Why

Measured with gitleaks 8.30.1 (details in [docs/design.md](docs/design.md) §2):

- its default rules missed 3 of 7 planted leak kinds: a URL with an inline
  password, a key split across two string literals, a literal cloud account id;
- it scans neither commit messages nor file paths;
- it skips binary-looking files and its own config files, silently;
- on an empty tree it reports "scanned ~0 bytes" and exits 0.

## What it does

| layer | what | effect |
|---|---|---|
| 1 | gitleaks over the index, the history and the change, plus structural checks; the tree's bytes must balance and the commit counts must match git's | fails the scan |
| 2 | the change's diff, masked and proved masked, reviewed by four model roles through [Vornik](https://vornik.io) | a pull-request comment only |
| 3 | every model claim and reason checked against the diff, deterministically | drops what it cannot tie to the diff |
| 4 | a planted set of fake secrets and decoys that measures layers 1 to 3 | fails a scheduled run |

Status: **layer 1 is built** (`secretscan scan`); layers 2 to 4 follow
(design §7).

## Use

```bash
scripts/install-gitleaks.sh          # pinned gitleaks, sha256-checked, into .tools/bin
go run ./cmd/secretscan scan --repo . --base origin/main --head HEAD \
  --gitleaks .tools/bin/gitleaks --ledgers ledgers --report layer1.jsonl
```

Exit status: 0 clean, 1 findings, 2 an error (never "clean"). Findings are
printed as path, line and rule; a value is never printed.

**Ledgers** exempt a named value or path, each with its reason, one
`<value>\t<reason>` per line: `accounts.allow` (12-digit values),
`names.allow` (key-file paths), `skip.allow` (files exempt from the stdin
rescan).

## Develop

`make check` runs gofmt, `go vet`, the tests (which drive the real gitleaks)
and this repository's own layer 1 scan.

## Licence

MIT. Copyright (c) 2026 EaseIT Labs s.r.o. and contributors.
