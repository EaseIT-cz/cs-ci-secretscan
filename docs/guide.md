# Adopting the layered secret scan on a repository that uses Vornik

This guide sets up all four layers of `secretscan` on a GitHub repository.
It takes about an hour, most of it waiting for approvals and the first CI
runs. You need four things: a Vornik installation the CI runners can reach over
HTTPS; an assistant connected to it with the admin tools (Vornik's companion
plugin, or any MCP client with the admin connection); `vornikctl` on the
Vornik host; admin rights on the repository. Below, `<ns>` is your Vornik
agent namespace, the prefix of every project the assistant creates.

## 1. Decide two things first

Write both decisions in the repository's design or security notes before
you build. They are the customer's, not the tool's.

| decision | what it means | our default |
|---|---|---|
| **What may leave the runner** | Layer 2 sends the change's diff to Vornik, which sends it to the models the roles use. Every value layer 1 finds and every 12-digit number is masked first, and a rescan proves it. A secret layer 1 misses is sent. | accept, and state the destination (provider and host) |
| **Where layer 2 runs** | Its job holds a Vornik key. On a shared runner that also runs pull requests' code, a leftover process could read it. | a separate runner if you have one; otherwise accept and record it |

Use a `pull_request` job for layer 2, not `pull_request_target`. The latter
runs with the base repository's credentials beside content a pull request
controls. Its one benefit here, stopping an author from editing the job to
skip the mask on their own change, protects nothing the author does not
already hold.

## 2. The deterministic layer (layer 1)

1. **Pin the tools.** Pin gitleaks by version and the sha256 of its release
   archive (this repository's `scripts/install-gitleaks.sh` does both and
   installs it in `.tools/bin/`); install `secretscan` with `go install
   github.com/EaseIT-cz/cs-ci-secretscan/cmd/secretscan@<tag>`, which Go
   checks against `sum.golang.org`. Install both on every run, so every run
   checks them.
2. **Run it once by hand** and read what it reports. Use your repository's
   existing `.gitleaks.toml` if it has one; without `--config`, gitleaks'
   default rules apply:
   ```bash
   secretscan scan --repo . --base origin/main --head HEAD \
     --config .gitleaks.toml --gitleaks .tools/bin/gitleaks \
     --account-vars "$YOUR_ACCOUNT_IDS"
   ```
   Expect findings on the first run. Each is a path, a line and a rule.
3. **Resolve each finding by its nature, never in bulk:**
   - a real secret: remove it and rotate it;
   - a fake test value: build it at run time, or in parts, so no complete
     one is in the source;
   - a public value (an AWS documentation id, a public CA bundle): list it in
     a ledger with its reason (`accounts.allow`, `names.allow`);
   - a file gitleaks skips that holds no secret (`go.sum`): `skip.allow`,
     with its reason;
   - an inline allow marker (gitleaks' own): give it a reason, or remove it if it
     silences nothing; the scan reports both.
4. **Add the job.** Its own job, needing no other, so a failing lint or test
   cannot hide it; `fetch-depth: 0`; no credential; `--summary
   "$GITHUB_STEP_SUMMARY"`. Pass every account id variable to
   `--account-vars`: a missed one is a missed finding.

## 3. The Vornik review (layers 2 and 3)

1. **Create the team** with the admin tools. One project, `<ns>--secretscan`,
   with four roles on four different models: two hunters, a triager, an
   adjudicator. Give each role its own single-role workflow (`hunt-a`,
   `hunt-b`, `triage`, `adjudicate`) that takes the diff as a `text/x-diff`
   document and returns a bounded schema. The operator approves each change
   on a phone. Give string fields room: a model that overshoots a field's limit
   has its whole output withheld (`egress_schema`). Use separate workflows,
   not one with four steps: a Vornik workflow hands each step only the
   previous step's output.
2. **Mint the CI key** for that project, limited to its four workflows, with
   a budget and an expiry, and store it straight into the repository's
   secrets; it is printed once and never needs to be seen:
   ```bash
   vornikctl companion grant --project <ns>--secretscan --client github-actions \
     --workflows <ns>--secretscan--hunt-a,<ns>--secretscan--hunt-b,<ns>--secretscan--triage,<ns>--secretscan--adjudicate \
     --budget-usd 10 --expires 90d --json | jq -r .secret | gh secret set VORNIK_SECRETSCAN_TOKEN
   ```
3. **Add the job**, on pull requests only, with two steps that never share a
   token: `secretscan review ... --prefix <ns>--secretscan-- --out comment.md`
   with `VORNIK_TOKEN: ${{ secrets.VORNIK_SECRETSCAN_TOKEN }}` in its `env`,
   then `secretscan comment --file comment.md` with
   `GITHUB_TOKEN: ${{ github.token }}` in its `env`. Its
   permissions: `contents: read`, `pull-requests: write`.
4. **Read the first comment.** It states what was examined and masked, each
   confirmed finding with its confidence, the triage of layer 1's findings,
   and, if layer 2 did not complete, which workflow failed and why.

## 4. The self-test (layer 4)

Add a scheduled workflow: nightly `secretscan selftest layer1`, weekly
`secretscan selftest layer2`, each followed by `secretscan sweep` over the
step's log and summary (`if: always()`), and an issue on failure. Mirror the
CI key's expiry in a repository variable and fail 14 days ahead. After four weekly runs, set the floor and the ceiling in a floors file
(`FLOOR_DETECTIONS`, `CEILING_DECOYS`): the floor is the four runs' lowest
count of planted secrets the review confirmed, and a later run below it
fails; the ceiling is their median count of decoys it confirmed, and a
later run above it fails. A median, so one noisy run cannot raise it. The
sweep first plants one value in a control file and fails if it cannot find
it, so a broken sweep never reads as clean.

## 5. Verify end to end, with planted fake secrets

Open a pull request that adds random fake values of each kind, including a
key split across two string literals, and a decoy (a sha256 under a `*_sha`
name). Do not label them fake in the files: models read such a comment and
dismiss the value. Expect: layer 1 fails the pull request on every
rule-visible plant; the review confirms the split key; the decoy is not
reported; no planted value appears in either job's log. Close it unmerged
and delete the branch.

## What it does not cover

- A secret neither gitleaks, the structural checks nor the models recognise.
- A secret in a pull request's title or body.
- A secret in a binary file layer 2 is not sent (layer 1 still reads it).
- About 1.1% of random tokens under a key name, which gitleaks' generic rule
  drops by its stopword list (measured); layer 2 may still catch them.
