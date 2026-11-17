# Case study: using Vornik to build and operate CI secret scanning

**In short.** In two days, an assistant working through Vornik built a
four-layer secret scan for a private infrastructure repository and put it
into production CI. Vornik was used in both of its modes: in **companion
mode** it reviewed every design and change and kept the project's memory
while the assistant built; in **autonomous execution** it now runs a team
of four model roles on every pull request. On a pull request planted with fake secrets, the deterministic layer failed
the change on all five plants its rules can see (gitleaks' rules plus the
structural checks this work added), and Vornik's team confirmed, at high
confidence, a key split across two string literals that no rule could see. Every figure
below was measured on 2026-11-16 and 2026-11-17; each states its scope.

## The problem

The repository (Go and OpenTofu: 673 files, 852 commits) already ran
gitleaks in CI. Measured with gitleaks 8.30.1, that was not enough:

| measured | result |
|---|---|
| seven planted kinds of leak | 4 found; **missed** a URL with an inline password, a key split across two string literals, a literal cloud account id |
| commit messages and file paths | **never scanned** |
| a file with a NUL byte; its own config files | **skipped**, silently |
| an empty tree or repository | "scanned ~0 bytes", exit 0: clean |
| random 40-character tokens under a key name | **1.1% dropped** by the generic rule's stopword list (23 of 2,000) |
| the scan's position in CI | after lint and tests: a failing pull request was never scanned |
| inline allow markers in the tree | 13 of 22 silenced nothing |

And the repository's GitHub plan offered no push protection: a pushed
GitHub-token-shaped value was accepted.

## What was built

[`secretscan`](https://github.com/EaseIT-cz/cs-ci-secretscan) (MIT) wraps
gitleaks in four layers:

1. **Deterministic, and it proves what it examined:**
   - gitleaks over the index, the history and the change;
   - the tree's bytes must balance exactly against the files gitleaks names
     as skipped, and those files are rescanned;
   - commit messages and paths are scanned;
   - commit counts must match git's, and shallow clones are refused;
   - structural checks catch what gitleaks' rules miss.
   On the repository: 125,686 lines through the structural checks in 4.3 s.
2. **Vornik's review team** reads the change's diff, masked first and proved
   masked by a rescan: two hunters on different models, a triager for layer
   1's findings, an adjudicator. It comments; it never blocks.
3. **A deterministic check of every model claim**: the line must be an added
   line, unmasked, of the right shape; a reason may not echo the value or
   carry markup.
4. **A self-test** on a fresh planted set, nightly through layer 1 and weekly
   through the review, with every output swept for every planted value.

## Building it: Vornik in companion mode

The assistant (Claude Code) worked with Vornik's companion plugin and admin
tools:

- **Reviews until GREEN.** The design was reviewed by Vornik's
  architectural-review workflow before any code: the as-built record in two
  rounds, the four-layer change in four parts (the whole exceeded the
  reviewer's output) over up to five rounds each, and every code change
  after. The reviews caught real defects: masking by gitleaks' columns would
  have leaked each value's first character; the denominators could pass on a
  shallow clone; a flat entropy floor
  would have dropped 78% of random 20-hex secrets (20,000 sampled).
- **Project memory.** Measurements, decisions and dead ends were stored in
  Vornik's memory as they happened, and recalled before each design step.
- **The team, built through the admin tools.** One project, four roles on
  four models, four workflows and a scoped CI key, each approved by the
  operator on a phone. The key went straight from Vornik into the
  repository's secrets; no person or model saw it.

## Operating it: Vornik's autonomous execution

On every pull request, CI masks the diff and calls Vornik's four broker
workflows; Vornik runs each role in its own container with no network,
checks each output against its approved schema, and returns only those
fields.

**End to end, on a pull request planted with fake secrets:**

| plant | layer | result |
|---|---|---|
| GitHub token, AWS secret key, URL with a password, account id, token in the commit message | 1 | the pull request **failed**, each finding printed by path, line and rule |
| a key split across two string literals | 2 | **confirmed at high confidence**, by both hunters |
| a sha256 under a `*_sha` name (decoy) | all | not reported |
| all eight planted values (the seven plants above, the split key counting as two halves) | outputs | **in neither job's log** (923 lines searched; the search first found a value planted in a control file) |

One review of that 16-line change took 3 min 18 s and about **$0.15** of
model spend (the agents' own estimates over 18 calls). On a real 304-line
change, the review completed and found nothing, correctly.

## What testing on real pull requests found

Ten defects reached the planted and real pull requests that unit tests had
not caught; each was fixed with a test at the level where it was found:

- a relative tool path broke the mask, which failed closed and said "the
  mask did not hold" instead of naming the tool error;
- a 77 KB diff exceeded what a hunter could read within Vornik's
  30-iteration tool limit, so a review now sends at most 24 KiB, code first;
- a hunter correctly called a split hex key `private_key`, and a per-class
  shape check dropped it; shapes are now checked by family;
- model output over its schema's limits was withheld by Vornik
  (`egress_schema`), and the comment did not say so;
- one of four account variables was not passed;
- a diff on a base that had moved showed the base's changes, reversed.

**Two lessons about models.** A comment saying "every value here is fake"
talked both the triager and the adjudicator into dismissing real-looking
secrets: the deterministic layer stays the gate for that reason. And
failing open is only safe when each failure says exactly why.

## What Vornik needs next

Found while building, filed with Vornik's maintainers:

- **Companion keys bound to a GitHub OIDC claim**, so CI holds no stored
  secret (on a free private repository, any pushed branch can read every
  repository secret).
- **An approved workflow change was rejected at apply** while its new
  definition was stored, leaving the workflow unusable until it was removed
  and recreated.
- Roles' iteration and token limits are not settable through the admin
  tools, so long diffs are cut rather than read whole.
- A project's task concurrency is fixed at one, so the four roles run in
  turn: 3 min 10 s for a review that would take about 1 min 50 s with the
  first three together.

## Try it

The tool and its design are public:
[EaseIT-cz/cs-ci-secretscan](https://github.com/EaseIT-cz/cs-ci-secretscan).
To adopt it on a repository that uses Vornik, follow
[the guide](guide.md).
