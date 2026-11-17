# cs-ci-secretscan

**A case study: using [Vornik](https://vornik.io) to build and operate CI
secret scanning.**

`secretscan` runs a repository's secret scan in four layers. Deterministic
checks around [gitleaks](https://github.com/gitleaks/gitleaks) catch what
rules can see and prove what they examined. Vornik's team of four model
roles, each on a different model, reviews every change for what rules
cannot see: a key split across two strings, a credential in a fixture, a
secret moved into a comment. Deterministic checks then verify every claim
the models make.

Vornik is used in both of its modes:
- **companion mode built it:** an assistant wired to Vornik designed,
  reviewed and implemented this, with Vornik's delegated reviews, project
  memory and admin tools;
- **autonomous execution operates it:** on every pull request, Vornik runs
  the review team as broker workflows, triggered from CI with a scoped key.

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
| 2 | Vornik's review team (two independent hunters, a triager, an adjudicator) reads the change's diff, masked and proved masked | a pull-request comment |
| 3 | every model claim and reason checked against the diff, deterministically | drops what it cannot tie to the diff |
| 4 | a planted set of fake secrets and decoys that measures layers 1 to 3 | fails a scheduled run |

Status: **all four layers are built**: `secretscan scan` (layer 1),
`secretscan review` (layers 2 and 3, through Vornik), and `secretscan
selftest`, `sweep` and `completion` (layer 4, the planted set and the
denominators) (design §6, §7).

## Use

```bash
scripts/install-gitleaks.sh          # pinned gitleaks, sha256-checked, into .tools/bin
go run ./cmd/secretscan scan --repo . --base origin/main --head HEAD \
  --gitleaks .tools/bin/gitleaks --ledgers ledgers --report layer1.jsonl
```

Exit status: 0 clean, 1 findings, 2 an error (never "clean"). Findings are
printed as path, line and rule; a value is never printed.

```bash
VORNIK_TOKEN=… GITHUB_TOKEN=… go run ./cmd/secretscan review --repo . \
  --base origin/main --head HEAD --vornik-url https://vornik.example/api/v1/mcp/companion \
  --prefix ns--secretscan-- --pr 42 --repository owner/name --gitleaks .tools/bin/gitleaks
```

`review` masks the diff and proves the mask, runs Vornik's four review
workflows, checks every claim, and posts one comment. Tokens come from the
environment only. It exits 0 whatever happened: layer 2 comments.

**Ledgers** exempt a named value or path, each with its reason, one
`<value>\t<reason>` per line: `accounts.allow` (12-digit values),
`names.allow` (key-file paths), `skip.allow` (files exempt from the stdin
rescan).

## Read more

- [The case study](docs/case-study.md): Vornik building and operating this,
  with every figure measured.
- [The adoption guide](docs/guide.md): set it up on a repository that uses
  Vornik.
- [The design](docs/design.md).

## Develop

`make check` runs gofmt, `go vet`, the tests (which drive the real gitleaks)
and this repository's own layer 1 scan.

## Licence

MIT. Copyright (c) 2026 EaseIT Labs s.r.o. and contributors.
