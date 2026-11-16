package secretscan

import (
	"strconv"
	"strings"
	"testing"
)

// Layer 1's deterministic checks (docs/design.md).
// Every value below is fake; none is a credential.

func TestParseLedger(t *testing.T) {
	l, err := ParseLedger("accounts.allow", strings.NewReader(
		"# AWS's documentation ids\n\n111122223333\tAWS documentation example\n123456789012\tAWS documentation example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !l.Has("111122223333") || !l.Has("123456789012") || l.Has("359545463725") {
		t.Fatalf("ledger membership wrong: %v", l)
	}
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
}

func TestParseLedgerRefusesMalformedLines(t *testing.T) {
	for name, in := range map[string]string{
		"no tab":       "111122223333 AWS documentation example\n",
		"empty reason": "111122223333\t \n",
		"empty value":  "\tsome reason\n",
		"two tabs":     "111122223333\ta\tb\n",
		"duplicate":    "111122223333\ta\n111122223333\tb\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseLedger("accounts.allow", strings.NewReader(in))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), "accounts.allow:") {
				t.Fatalf("error %q does not name the file and line", err)
			}
		})
	}
}

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestCheckPath(t *testing.T) {
	names, _ := ParseLedger("names.allow", strings.NewReader(
		"internal/dbpool/rds-ca-eu-central-1.pem\tAWS's public CA bundle\n"))
	c := Checker{Names: names}
	for path, want := range map[string]string{
		"deploy/key.pem":                           RuleKeyFile,
		"secrets/server.key":                       RuleKeyFile,
		"home/id_rsa":                              RuleKeyFile,
		"home/id_ed25519.pub":                      RuleKeyFile,
		"infra/envs/prod/terraform.tfstate":        RuleKeyFile,
		"infra/envs/prod/terraform.tfstate.backup": RuleKeyFile,
		"infra/prod.tfvars":                        RuleKeyFile,
		".env":                                     RuleKeyFile,
		"cmd/x/.env.local":                         RuleKeyFile,
		"a/.tools/bin/x":                           RuleCachePath,
		".terraform/providers/x":                   RuleCachePath,
		"infra/errored_test.tfstate":               RuleCachePath,
		"testdata/fixtures/key.pem":                "",
		"internal/dbpool/rds-ca-eu-central-1.pem":  "",
		"docs/environment.md":                      "",
		"internal/keys/keyring.go":                 "",
	} {
		got := rules(c.CheckPath(path))
		if want == "" && len(got) != 0 {
			t.Errorf("%s: got %v, want no finding", path, got)
		}
		if want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("%s: got %v, want [%s]", path, got, want)
		}
	}
}

// pemBegin is split from each header so this file holds no complete PEM
// private-key header for the repository's own secret scan to find.
const pemBegin = "-----" + "BEGIN "

// fakeDBURL is a URL with a fake inline password, built in parts so this
// file holds no complete one.
const fakeDBURL = `db = "postgres://ops:` + `QxveOXaW!9@db.example:5432/x"`

func TestCheckLine(t *testing.T) {
	accounts, _ := ParseLedger("accounts.allow", strings.NewReader(
		"111122223333\tAWS documentation example\n333333333333\trepeated-digit test id\n"))
	c := Checker{Accounts: accounts, AccountVars: []string{"154480844551"}}
	for line, want := range map[string][]string{
		pemBegin + "RSA PRIVATE KEY-----":                     {RulePEMKey},
		pemBegin + "PRIVATE KEY-----":                         {RulePEMKey},
		pemBegin + "OPENSSH PRIVATE KEY-----":                 {RulePEMKey},
		pemBegin + "ENCRYPTED PRIVATE KEY-----":               {RulePEMKey},
		"-----BEGIN CERTIFICATE-----":                         nil,
		fakeDBURL:                                             {RuleURLPassword},
		"https://user@example.com/path":                       nil,
		"see https://example.com/a@b and https://x.example/":  nil,
		`partner_account_id = "359545463725"`:                 {RuleAccountID},
		"arn:aws:iam::111122223333:role/x":                    nil,
		"bucket-333333333333":                                 nil,
		"id 154480844551 in a comment":                        {RuleAccountID},
		"a 13-digit number 3595454637251 is not an id":        nil,
		"sha a25d5e5bf684845d5ee99fa21cd50892138bdfdfd28d447": nil,
	} {
		got := rules(c.CheckLine(line))
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: got %v, want %v", line, got, want)
		}
	}
}

// An account variable's value is a finding even when the ledger lists it:
// the repository's own accounts never belong in the tree.
func TestAccountVariableBeatsTheLedger(t *testing.T) {
	accounts, _ := ParseLedger("accounts.allow", strings.NewReader("154480844551\twrongly listed\n"))
	c := Checker{Accounts: accounts, AccountVars: []string{"154480844551"}}
	if got := rules(c.CheckLine("x = 154480844551")); len(got) != 1 || got[0] != RuleAccountID {
		t.Fatalf("got %v, want [%s]", got, RuleAccountID)
	}
}

const debugLog = `2:51PM DBG skipping file: global allowlist path=.gitleaks.toml
2:51PM DBG skipping file: global allowlist path=go.sum
2:51PM DBG skipping empty file path=testdata/empty.tfvars
2:51PM INF scanned ~5262561 bytes (5.26 MB) in 547ms
2:51PM INF no leaks found
`

func TestParseScanLog(t *testing.T) {
	l, err := ParseScanLog(strings.NewReader(debugLog))
	if err != nil {
		t.Fatal(err)
	}
	if l.ScannedBytes != 5262561 {
		t.Fatalf("ScannedBytes = %d", l.ScannedBytes)
	}
	want := []string{".gitleaks.toml", "go.sum", "testdata/empty.tfvars"}
	if strings.Join(l.Skipped, ",") != strings.Join(want, ",") {
		t.Fatalf("Skipped = %v, want %v", l.Skipped, want)
	}
}

func TestParseScanLogRefusesALogWithoutTheByteCount(t *testing.T) {
	if _, err := ParseScanLog(strings.NewReader("2:51PM INF no leaks found\n")); err == nil {
		t.Fatal("a log with no scanned-bytes line must be an error, never 0 bytes")
	}
}

// The measured case of §8.4.1: 5,278,546 tracked bytes, 15,985 of them in
// files gitleaks names as skipped, 5,262,561 scanned.
func TestBalance(t *testing.T) {
	sizes := map[string]int64{"a.go": 5262561 - 100, "b.go": 100, ".gitleaks.toml": 15000, "go.sum": 985, "testdata/empty.tfvars": 0}
	l := ScanLog{ScannedBytes: 5262561, Skipped: []string{".gitleaks.toml", "go.sum", "testdata/empty.tfvars"}}
	b, err := CheckBalance(sizes, l)
	if err != nil {
		t.Fatal(err)
	}
	if b.TrackedFiles != 5 || b.TrackedBytes != 5278546 || b.SkippedFiles != 3 || b.SkippedBytes != 15985 {
		t.Fatalf("balance %+v", b)
	}
}

func TestBalanceRefusesAShortfallAnUnknownSkipAndAnEmptyTree(t *testing.T) {
	sizes := map[string]int64{"a.go": 1000, "b.go": 500}
	for name, l := range map[string]ScanLog{
		"a file skipped silently":     {ScannedBytes: 1000},
		"more bytes than tracked":     {ScannedBytes: 1600},
		"a skip of an untracked file": {ScannedBytes: 1500, Skipped: []string{"c.go"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CheckBalance(sizes, l); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := CheckBalance(map[string]int64{}, ScanLog{}); err == nil {
		t.Fatal("an empty tree must be an error, never clean")
	}
}

func TestMarkers(t *testing.T) {
	lines := map[Loc]string{
		{"a.tf", 3}:  `state_path = "infra/envs/prod/edge" # ` + marker + ` a state path fixture`,
		{"a.tf", 9}:  `x = "y" # ` + marker,
		{"b.sh", 12}: `printf 'x' # ` + marker + ` a fixture, but nothing fires here`,
	}
	fired := map[Loc]bool{{"a.tf", 3}: true, {"a.tf", 9}: true}
	fs := CheckMarkers(lines, fired)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Path+":"+strconv.Itoa(f.Line)] = f.Rule
	}
	want := map[string]string{"a.tf:9": RuleMarkerNoReason, "b.sh:12": RuleMarkerSilencesNothing}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestFindingsCarryNoValue(t *testing.T) {
	c := Checker{}
	for _, f := range c.CheckLine(fakeDBURL) {
		if strings.Contains(f.String(), "QxveOXaW") {
			t.Fatalf("finding %q carries the value", f.String())
		}
	}
}
