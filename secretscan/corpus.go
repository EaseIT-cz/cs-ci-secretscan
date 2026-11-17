package secretscan

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Plant is one planted fake value in the layer 4 corpus (docs/design.md
// §6). Layer is the layer expected to find it: 1 (with Rule) or 2. A decoy
// must be found by no layer.
type Plant struct {
	Kind  string
	Path  string // a file, CommitMessagesName or PathListName
	Line  int
	Rule  string // the layer 1 rule expected, for layer 1 plants
	Layer int
	Decoy bool
	Value string // the planted value; never printed
}

// Corpus is a git repository with a base commit and a commit of plants.
type Corpus struct {
	Dir        string
	Base, Head string
	Plants     []Plant
}

// CorpusAccounts is the accounts ledger the corpus is scanned with: AWS's
// documentation id is a decoy, listed as it would be in a real ledger.
const CorpusAccounts = "111122223333\tAWS documentation example account id\n"

func randAlnum(n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(a))))
		b[i] = a[k.Int64()]
	}
	return string(b)
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randAccount() string {
	for {
		n, _ := rand.Int(rand.Reader, big.NewInt(800_000_000_000))
		v := fmt.Sprintf("%012d", n.Int64()+100_000_000_000)
		if v != "111122223333" {
			return v
		}
	}
}

// NewCorpus writes a fresh planted set into dir (an empty directory). All
// values are random and fake by construction. Each value a gitleaks rule
// should catch is checked with gitleaks and drawn again if gitleaks misses
// it: gitleaks' generic rule drops about 1.1% of random 40-character
// tokens by its stopword allowlist (measured, 2,000 tokens), and the
// nightly gate tests the pipeline, not that rate, which is reported. The plant files carry no
// comment saying so: a model reads such a comment and dismisses the value
// (measured 2026-11-16), which is a different test.
func NewCorpus(dir, gitleaks string) (*Corpus, error) {
	c := &Corpus{Dir: dir}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=corpus@example.invalid", "-c", "user.name=corpus"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("corpus: git %s: %w", args[0], err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	write := func(p, content string) error {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, []byte(content), 0o644)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if _, err := git("init", "-q", "-b", "main"); err != nil {
		return nil, err
	}
	if err := write("README.md", "# service\n"); err != nil {
		return nil, err
	}
	if _, err := git("add", "-A"); err != nil {
		return nil, err
	}
	if _, err := git("commit", "-q", "-m", "initial"); err != nil {
		return nil, err
	}
	base, err := git("rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	c.Base = base

	detectable := func(gen func() string, line func(string) string) (string, error) {
		for i := 0; i < 20; i++ {
			v := gen()
			fs, err := runGitleaksStdin(gitleaks, "", dir, []byte(line(v)+"\n"))
			if err != nil {
				return "", err
			}
			if len(fs) > 0 {
				return v, nil
			}
		}
		return "", fmt.Errorf("corpus: no detectable value in 20 draws")
	}
	tok := func() string { return "gh" + "p_" + randAlnum(36) }
	ghp, err := detectable(tok, func(v string) string { return "GITHUB_TOKEN=" + v })
	if err != nil {
		return nil, err
	}
	ghpB64 := tok()
	cf, err := detectable(func() string { return randAlnum(40) }, func(v string) string { return "  CF_TOKEN: " + v })
	if err != nil {
		return nil, err
	}
	aws, err := detectable(func() string { return randAlnum(40) }, func(v string) string { return "AWS_SECRET_ACCESS_KEY=" + v })
	if err != nil {
		return nil, err
	}
	pw := randAlnum(12) + "K9!"
	acct := randAccount()
	h1, h2 := randHex(10), randHex(10)
	msgTok := "gh" + "p_" + randAlnum(36)
	pathTok := "gh" + "p_" + randAlnum(36)
	binTok := "gh" + "p_" + randAlnum(36)
	cfgTok := "gh" + "p_" + randAlnum(36)
	decoySHA := randHex(32)

	files := map[string]string{
		"config/app.env":         "GITHUB_TOKEN=" + ghp + "\nAWS_SECRET_ACCESS_KEY=" + aws + "\n",
		"deploy/workflow.yaml":   "env:\n  CF_TOKEN: " + cf + "\n",
		"infra/db.tf":            "locals {\n  db_url = \"postgres://ops:" + pw + "@db-17.internal.example:5432/app\"\n}\n",
		"infra/partner.tf":       "locals {\n  partner_account_id = \"" + acct + "\"\n  docs_example_id    = \"111122223333\"\n  release_bucket_sha = \"" + decoySHA + "\"\n}\n",
		"cmd/app/bootstrap.go":   "package main\n\nvar bootstrap = mustDecode(\"" + base64.StdEncoding.EncodeToString([]byte(ghpB64)) + "\")\n",
		"internal/sign/sign.go":  "package sign\n\n// key returns the manifest signing key.\nfunc key() string {\n\tpart1 := \"" + h1 + "\"\n\tpart2 := \"" + h2 + "\"\n\treturn part1 + part2\n}\n",
		"internal/sign/env.go":   "package sign\n\nimport \"os\"\n\nvar apiKey = os.Getenv(\"SIGNING_API_KEY\")\n",
		"deploy/server.key":      randHex(16) + "\n",
		"certs/k.txt":            "-----" + "BEGIN PRIVATE KEY-----\n",
		"data/blob.bin":          "\x00\x01\x02TOKEN=" + binTok + "\n",
		".gitleaks.toml":         "# token = " + cfgTok + "\n",
		"notes/" + pathTok + "/": "",
	}
	for p, content := range files {
		if strings.HasSuffix(p, "/") {
			if err := write(p+"readme.txt", "notes\n"); err != nil {
				return nil, err
			}
			continue
		}
		if err := write(p, content); err != nil {
			return nil, err
		}
	}
	if _, err := git("add", "-A"); err != nil {
		return nil, err
	}
	if _, err := git("commit", "-q", "-m", "add service config "+msgTok); err != nil {
		return nil, err
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	c.Head = head
	c.Plants = []Plant{
		{Kind: "github token", Path: "config/app.env", Line: 1, Rule: "github-pat", Layer: 1, Value: ghp},
		{Kind: "AWS secret key", Path: "config/app.env", Line: 2, Rule: "generic-api-key", Layer: 1, Value: aws},
		{Kind: "token under a key name", Path: "deploy/workflow.yaml", Line: 2, Rule: "generic-api-key", Layer: 1, Value: cf},
		{Kind: "URL with a password", Path: "infra/db.tf", Line: 2, Rule: RuleURLPassword, Layer: 1, Value: pw},
		{Kind: "account id", Path: "infra/partner.tf", Line: 2, Rule: RuleAccountID, Layer: 1, Value: acct},
		{Kind: "base64-encoded token", Path: "cmd/app/bootstrap.go", Line: 3, Rule: "github-pat", Layer: 1, Value: ghpB64},
		{Kind: "key file name", Path: "deploy/server.key", Rule: RuleKeyFile, Layer: 1},
		{Kind: "PEM private key header", Path: "certs/k.txt", Line: 1, Rule: RulePEMKey, Layer: 1},
		{Kind: "token in a binary file", Path: "data/blob.bin", Line: 1, Rule: "github-pat", Layer: 1, Value: binTok},
		{Kind: "token in a gitleaks config", Path: ".gitleaks.toml", Line: 1, Rule: "github-pat", Layer: 1, Value: cfgTok},
		{Kind: "token in a commit message", Path: CommitMessagesName, Rule: "github-pat", Layer: 1, Value: msgTok},
		{Kind: "token in a path", Path: PathListName, Rule: "github-pat", Layer: 1, Value: pathTok},
		{Kind: "key split across two literals", Path: "internal/sign/sign.go", Line: 5, Layer: 2, Value: h1 + h2},
		{Kind: "decoy: sha256 under a *_sha name", Path: "infra/partner.tf", Line: 4, Decoy: true, Value: decoySHA},
		{Kind: "decoy: AWS documentation id", Path: "infra/partner.tf", Line: 3, Decoy: true},
		{Kind: "decoy: environment lookup", Path: "internal/sign/env.go", Line: 5, Decoy: true},
	}
	return c, nil
}

// Values returns every planted value, for the no-value sweep.
func (c *Corpus) Values() []string {
	var out []string
	for _, p := range c.Plants {
		if p.Value != "" {
			out = append(out, p.Value)
			if p.Layer == 2 && len(p.Value) == 40 {
				out = append(out, p.Value[:20], p.Value[20:])
			}
		}
	}
	return out
}

// PlantResult is one plant's outcome.
type PlantResult struct {
	Plant
	Found bool
}

// CheckLayer1 matches layer 1's findings against the corpus: every layer 1
// plant must be found with its rule, and no decoy's line may be flagged.
func CheckLayer1(c *Corpus, fs []Finding) []PlantResult {
	var out []PlantResult
	for _, p := range c.Plants {
		if p.Layer == 2 {
			continue
		}
		found := false
		for _, f := range fs {
			pathOK := f.Path == p.Path || strings.HasPrefix(f.Path, p.Path+" ")
			lineOK := p.Line == 0 || p.Path == CommitMessagesName || p.Path == PathListName || f.Line == p.Line
			if p.Decoy {
				if f.Path == p.Path && f.Line == p.Line {
					found = true
				}
				continue
			}
			if pathOK && lineOK && f.Rule == p.Rule {
				found = true
			}
		}
		out = append(out, PlantResult{p, found})
	}
	return out
}
