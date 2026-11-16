# secretscan: design

Date: 2026-11-16 · Status: **design, carried over from a reviewed integration
design (below); built in stages, each stage marked.** Measurements are with
gitleaks 8.30.1 on a 670-file, 852-commit Go and OpenTofu repository, on a
development host, unless marked.

## 1. What it is, and why

`secretscan` runs a repository's secret scan in four layers. gitleaks alone
misses whole classes of leak and can report clean without having looked.
secretscan wraps it with checks that can fail, counts that must balance, and
Vornik's model review team, whose findings deterministic checks verify. The
case study's frame: Vornik in companion mode builds the scan, and Vornik's
autonomous execution operates its model layer on every change.

| layer | what | kind | effect |
|---|---|---|---|
| 1 | gitleaks, structural checks, checked denominators | deterministic | fails the scan |
| 2 | Vornik's review team on the masked diff | model | a pull-request comment |
| 3 | a check of every layer 2 claim and reason | deterministic | drops what it cannot tie to the diff |
| 4 | a planted set that measures layers 1 to 3 | deterministic harness | fails a scheduled run |

**Provenance.** This design was first written and reviewed as an integration
design inside one consuming repository (four parts, up to five review rounds
each, all GREEN on 2026-11-16). That record stays with the consumer. This
document holds the tool's half: what secretscan does in any repository. Each
consumer keeps its own integration: runner, workflow files, Vornik project,
and its decisions on data leaving the runner.

## 2. What gitleaks does and does not do (measured)

| behaviour | measured |
|---|---|
| default rules on seven planted kinds | found 4: a `ghp_` token, the same token base64-encoded (gitleaks decodes base64), a 40-character token under a key name, an AWS secret key under its usual name; **missed 3**: a URL with an inline password, a 40-hex key split into two string literals, a literal 12-digit AWS account id |
| an empty directory, an empty repository | prints "scanned ~0 bytes" and exits 0 |
| a file with a NUL byte | skipped, silently, by `gitleaks dir`; **read** by `gitleaks stdin` |
| gitignored files, a 3 MB file | scanned by `gitleaks dir`; no default size limit |
| its own config files, `go.mod`, `go.sum`, `*.bin` | skipped by its built-in allowlist |
| commit messages, file paths | **not scanned** by `gitleaks git` |
| column numbers | exact on a file's first line; on every later line one character late, and `EndColumn` can pass the end of the line |
| `--log-level debug` | names every skipped file and why; carries no candidate value |
| `--log-level trace` | **prints discarded candidate values** (`finding=…`), even with `--redact` |
| commit count | "N commits scanned" equals the non-merge commits that add a line (7 of 7 on a range, 620 of 620 on a whole history) |
| `--ignore-gitleaks-allow` | rescans as if no inline marker existed |

## 3. Layer 1: deterministic

`secretscan scan` (§7). It never prints a value: a finding is a path, a line
and a rule. It runs gitleaks at `--log-level debug` and refuses `trace`.

- **The tree, from the index.** `git checkout-index -a` exports exactly the
  tracked files to a scratch directory; `gitleaks dir .` runs inside it.
- **The tree's byte balance.** Tracked bytes, less the bytes of the files
  gitleaks names as skipped, must equal gitleaks' scanned bytes, exactly.
  Measured: 5,278,546 − 15,985 = 5,262,561, gitleaks' figure. A difference,
  a skip of an untracked file, a log without a byte count, or an empty tree
  fails the scan.
- **Every skipped file is scanned again** through `gitleaks stdin`, unless the
  skip ledger names it with a reason. That ledger exempts a file from the
  stdin rescan only; the structural checks still read it.
- **The range** (`--base`, `--head`): `gitleaks git --log-opts=<base>..<head>`,
  so a finding is reported as the change's. **The history**: every commit.
  Each run's commit count must equal the non-merge commits of its range that
  add a line. A shallow clone is refused outright (`git rev-parse
  --is-shallow-repository`): git and gitleaks see the same truncated
  history, so their counts agree and could not catch it (found by test).
- **Messages and paths**: every commit message and every path in the history,
  and the range's on their own, through `gitleaks stdin`. Measured on the
  repository above: 749,949 bytes in 0.56 s.
- **Structural checks**, on files read as bytes, binary ones included, each run
  over the range's added lines and over the whole tree:
  - a file name that holds keys or state (`*.pem`, `*.key`, `id_rsa*`,
    `id_ed25519*`, `*.tfstate*`, `*.tfvars`, `.env`, `.env.*`), outside a
    `testdata/` directory, unless the names ledger lists it;
  - a PEM private-key header;
  - a URL whose authority holds a user, a colon, a password and an `@`
    before the host;
  - a run of exactly 12 digits that equals one of the consumer's own account
    ids (always a finding), or that the accounts ledger does not list;
  - a tracked file under `.tools/`, `.terraform/` or named
    `errored_test.tfstate`: caches a gitleaks config commonly allowlists by
    path, so a committed file there would never be scanned.
- **Markers.** gitleaks' inline allow marker (the word `gitleaks`, a colon,
  `allow`) must be followed by its reason. A reasoned marker exempts its
  line from gitleaks and from the structural checks alike, since gitleaks
  never fires on the structural rules and a fixture such as a disposable
  test database's URL needs one way to be exempted. A marker must sit on a
  line where some layer 1 rule fires: gitleaks run with
  `--ignore-gitleaks-allow`, or a structural check. One that silences
  nothing is a standing permission for whatever a later edit puts there.
- **The report** (`layer1.jsonl`): per finding its fingerprint, path, start
  and end line, rule, and masked context. No gitleaks `Line`, `Match` or
  `Secret` field.

**Ledgers.** Plain text, one `<value>\t<reason>` per line, `#` comments. A
line without exactly one tab, an empty field or a duplicate is an error.
Three ledgers: `accounts.allow` (12-digit values), `names.allow` (key-file
paths), `skip.allow` (paths exempt from the stdin rescan).

## 4. Layer 2: Vornik's review of the masked diff

**The mask** (`secretscan mask`) anchors on lines, not gitleaks' columns
(§2). For each layer 1 finding, on every line from its start to its end line,
it replaces with `[REDACTED:<rule>]` each whitespace- or quote-delimited
token the finding's span, widened by one character each side, overlaps. It
replaces every run of 12 digits, plain or split by `-` or spaces, with
`[REDACTED:account-id]`. It applies the same to `layer1.jsonl`'s context.
**It then proves the mask held:** gitleaks and the structural checks run
again over the masked diff and the masked report. Any finding refuses the
send. A diff is cut at file boundaries into runs of at most 256 KiB; a file
over the cap is reported not examined.

**The review** (`secretscan review`) sends the masked diff to four Vornik
broker workflows, each one role on its own model: two independent hunters,
a triager for layer 1's findings, and an adjudicator. The hunters and the
triager run at once; the adjudicator runs after layer 3. Separate workflows,
because a Vornik workflow hands each step only the previous step's output
(measured: in one four-step workflow, the first hunter's claims never
reached the adjudicator, and the second hunter could read the first's).
Every string Vornik returns arrives wrapped as
`<untrusted_content source="broker_egress">\n…\n</untrusted_content>`;
secretscan strips exactly that and refuses any other shape.

**Failing open.** Any layer 2 error ends the step successfully with a report
that layer 2 did not complete and why. Layer 1 is unaffected.

**What leaves the runner.** The masked diff. A secret layer 1 misses is sent
unmasked; on the planted set, with the structural checks, that is one kind
of seven (the split key). Vornik does not scan workflow inputs (measured).
Whether that is acceptable is each consumer's decision.

## 5. Layer 3: deterministic check of every claim and reason

`secretscan verify` reads the unmasked diff in-process and never writes it.

**A claim survives only if** its path is in the diff, its line is an added
line, the line was not masked (a masked token is a layer 1 finding or a
listed 12-digit value; a claim on it is a counted duplicate), and the
unmasked line has the shape of the class:
- `cloud_account_id`: 12 digits, or 12 split by `-` or spaces;
- `connection_string`: `scheme://…@`;
- `encoded_blob`: base64 (standard or URL-safe, padding inside) of 16 or more
  characters, hex of 24 or more, or a percent-encoded run of 12 or more bytes;
- `token`, `api_key`, `password`: a run whose Shannon entropy over its own
  character frequencies reaches the floor for its alphabet and length;
- `private_key`: a PEM header or a base64 body of 64 or more characters;
- `internal_host`, `email`: a hostname or an address;
- `other`: only when both hunters claim the line.

**The entropy floor.** The alphabet is the first that holds the run: decimal,
hex `[0-9a-fA-F]`, alphanumeric `[A-Za-z0-9_-]`, base64
`[A-Za-z0-9+/=_-]`, printable (ASCII 33 to 126); any other character splits
the run. Minimum lengths: 24 hex, 16 base64, 16 decimal, 12 alphanumeric or
printable. The floor is the 1st percentile, by nearest rank, of 20,000
uniformly random strings of that alphabet and length, seed 289, one cell for
every length from the minimum to 64; a longer run uses the 64 cell.

| alphabet | 16 | 20 | 24 | 40 | 64 |
|---|---|---|---|---|---|
| decimal | 2.31 | 2.50 | 2.64 | 2.90 | 3.06 |
| hex | 2.66 | 2.90 | 3.04 | 3.40 | 3.63 |
| alphanumeric | 3.38 | 3.65 | 3.89 | 4.47 | 4.92 |
| base64 | 3.38 | 3.68 | 3.91 | 4.48 | 4.96 |
| printable | 3.45 | 3.78 | 4.02 | 4.65 | 5.16 |

A flat 3.5-bit floor would drop 90% of 16-hex, 78% of 20-hex and 54% of
24-hex random secrets (measured), including both halves of a split key. The
floor removes words and repeated characters, not names: an environment
variable name passes, and rejecting it is the adjudicator's job.

**Agreement** is computed here: same path, lines within 2, same class family
(credential: `token`, `api_key`, `password`, `private_key`,
`connection_string`, `encoded_blob`; identifier: `cloud_account_id`,
`internal_host`, `email`). Confidence is `high` when both hunters agree and
the adjudicator confirms, `medium` when one hunter's claim is confirmed. An
undecided claim is dropped and counted; a failed hunter caps confidence at
`medium`.

**A reason survives only if** it holds no 8-character run of its line's
unmasked text and has no `@`, backtick, `<`, `>`, `|`, `[`, `]`, `://`, `//`
or line break, and does not start with `-` or `#`; otherwise "(reason
withheld)". At most 20 claims and 6,000 characters of model text reach a
report; the rest is counted.

**Policy in code.** A layer 1 finding of `account-id` or `url-password`
stays `real_secret` whatever a model says.

## 6. Layer 4: the planted set

`secretscan corpus` writes a fresh planted set with random fake values: the
seven kinds of §2; a token in a commit message, in a path, in a binary file
and in a gitleaks config; and decoys (a sha256 under a `*_sha` name, an
environment lookup, an AWS documentation id, a public key fingerprint). A
consumer's scheduled run requires layer 1 to find every plant in its classes
and flag no decoy, and searches every output for every planted value, with a
positive control.

## 7. The command

| subcommand | stage |
|---|---|
| `scan`: layer 1 | built in stage 1 |
| `mask`, `verify`, `review`, `comment` | stage 2 |
| `corpus` | stage 3 |

Exit codes: 0 clean, 1 findings, 2 a tool or usage error (never "clean").

## 8. Running it in CI safely

- **Run layer 2 from trusted code.** A pull request's own workflow can be
  edited by the pull request. Run layer 2 from a `pull_request_target`
  workflow (the base branch's definition), check out the base, and read the
  pull request's commits only as fetched git objects through `git diff`,
  `git log` and `gitleaks git`. git reads attributes from the checked-out
  base tree, so a pull request's `.gitattributes` cannot attach a diff driver
  (measured). Run git with `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`, an empty `core.hooksPath`, and
  `--no-textconv --no-ext-diff`. Pass a fetch token in git's
  `GIT_CONFIG_COUNT`/`KEY`/`VALUE` environment, never on a command line.
- **Use the base branch's gitleaks config and ledgers,** so a change cannot
  weaken the rules that decide what is masked.
- **Full clones only** (`fetch-depth: 0`); a shallow clone is refused.
