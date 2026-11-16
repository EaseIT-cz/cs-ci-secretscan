package secretscan

import (
	"strings"
	"testing"
)

// Layer 3 (docs/design.md §5). Lines are fake.
const verifyDiff = `diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -10,1 +10,6 @@
   region = "eu-central-1"
+  release_bucket_sha = "a25d5e5bf68484bd574467ad5ee99fa21cd50892138bdfdfd28d447e296b0896"
+  name = "hello"
+  partner = "[REDACTED:account-id]"
+	part1 := "a39e382dd4865c0bd3ad"
+	part2 := "514e68cc07642da67d76"
+	c.apiKey = os.Getenv("VORNIK_CLOUD_API_KEY")
`

func pd(t *testing.T) ParsedDiff { return ParseDiff(verifyDiff) }

func TestShapeChecks(t *testing.T) {
	for _, c := range []struct {
		class, line string
		want        bool
	}{
		{"token", `part1 := "a39e382dd4865c0bd3ad"`, true}, // 20 hex: above its floor
		{"token", `name = "hello"`, false},
		{"token", `x = "aaaaaaaaaaaaaaaaaaaaaaaa"`, false},
		{"password", `pw = "QxveOXaWuNDy!9"`, true},                     // 14 printable
		{"token", `c.apiKey = os.Getenv("VORNIK_CLOUD_API_KEY")`, true}, // a name passes; the adjudicator judges it
		{"cloud_account_id", `id = "3595-4546-3725"`, true},
		{"cloud_account_id", `id = "35954546372"`, false},
		{"connection_string", "u = postgres://ops:" + "pw@db.example/x", true},
		{"connection_string", "u = https://example.com/x", false},
		{"encoded_blob", `b = "Z2hwXzhmcWpScE9vSEZyVERhTWRJOEts"`, true},
		{"encoded_blob", `b = "%41%42%43%44%45%46%47%48%49%4a%4b%4c"`, true},
		{"encoded_blob", `b = "short"`, false},
		{"private_key", "-----" + "BEGIN PRIVATE KEY-----", true},
		{"internal_host", "h = db-17.corp.example.lan", true},
		{"email", "who = ops@example.com", true},
		{"email", "who = nobody", false},
		{"other", "anything", false},
	} {
		if got := hasShape(c.class, c.line); got != c.want {
			t.Errorf("hasShape(%s, %q) = %v, want %v", c.class, c.line, got, c.want)
		}
	}
}

func TestVerifyDropsUntiedClaimsAndMergesAgreement(t *testing.T) {
	d := pd(t)
	claims := []Claim{
		{Path: "infra/main.tf", Line: 11, Class: "token", Reason: "a 64-hex value", By: "a"},      // the decoy: passes shape
		{Path: "infra/main.tf", Line: 12, Class: "token", Reason: "a word", By: "a"},              // no shape
		{Path: "infra/main.tf", Line: 13, Class: "cloud_account_id", Reason: "an id", By: "b"},    // a masked line
		{Path: "infra/main.tf", Line: 14, Class: "token", Reason: "first half of a key", By: "a"}, // agrees with b's api_key
		{Path: "infra/main.tf", Line: 15, Class: "token", Reason: "second half", By: "a"},
		{Path: "infra/main.tf", Line: 14, Class: "api_key", Reason: "split key", By: "b"},
		{Path: "infra/main.tf", Line: 10, Class: "token", Reason: "context line", By: "b"}, // not an added line
		{Path: "nowhere.go", Line: 1, Class: "token", Reason: "no such file", By: "b"},
		{Path: "infra/main.tf", Line: 16, Class: "other", Reason: "one hunter only", By: "a"},
	}
	r := Verify(claims, d)
	byLine := map[int]Candidate{}
	for _, c := range r.Candidates {
		byLine[c.Line] = c
	}
	if c, ok := byLine[14]; !ok || c.FoundBy != "both" {
		t.Errorf("the split key's first half: %+v (want found by both)", c)
	}
	if _, ok := byLine[11]; !ok {
		t.Error("the decoy passes the shape check; only the adjudicator can drop it")
	}
	for _, l := range []int{10, 12, 13, 16} {
		if _, ok := byLine[l]; ok {
			t.Errorf("line %d should have been dropped", l)
		}
	}
	for _, reason := range []string{"not an added line", "no shape", "masked line", "no such path", "other needs both"} {
		if r.Dropped[reason] == 0 {
			t.Errorf("no drop counted for %q: %v", reason, r.Dropped)
		}
	}
	for i, c := range r.Candidates {
		if want := "c" + string(rune('1'+i)); !strings.HasPrefix(c.ID, "c") || len(c.ID) != 3 {
			t.Errorf("candidate id %q, want c01-style (%s)", c.ID, want)
		}
	}
}

func TestReasonFilter(t *testing.T) {
	line := `part1 := "a39e382dd4865c0bd3ad"`
	for reason, ok := range map[string]bool{
		"half of a hex signing key, joined with the next line": true,
		"the value a39e382dd4865c0b is a key":                  false, // echoes 16 characters of the value
		"see https://attacker.example/x":                       false,
		"ping @maintainer":                                     false,
		"- looks like a list item":                             false,
		"a key | in a table":                                   false,
		"a password, in words":                                 true, // a plain word shared with code is not an echo
	} {
		if got := reasonSurvives(reason, line); got != ok {
			t.Errorf("reasonSurvives(%q) = %v, want %v", reason, got, ok)
		}
	}
}

func TestAdjudicateConfidenceAndPolicy(t *testing.T) {
	cands := []Candidate{
		{ID: "c01", Path: "a", Line: 1, Class: "token", FoundBy: "both"},
		{ID: "c02", Path: "a", Line: 2, Class: "token", FoundBy: "hunter_a"},
		{ID: "c03", Path: "a", Line: 3, Class: "token", FoundBy: "both"},
		{ID: "c04", Path: "a", Line: 4, Class: "token", FoundBy: "both"},
	}
	dec := map[string]string{"c01": "confirm", "c02": "confirm", "c03": "reject"} // c04 undecided
	fs, dropped := Adjudicate(cands, dec, false)
	conf := map[string]string{}
	for _, f := range fs {
		conf[f.ID] = f.Confidence
	}
	if conf["c01"] != "high" || conf["c02"] != "medium" || len(fs) != 2 {
		t.Fatalf("confidences %v", conf)
	}
	if dropped["rejected"] != 1 || dropped["undecided"] != 1 {
		t.Fatalf("dropped %v", dropped)
	}
	fs, _ = Adjudicate(cands, dec, true) // a hunter failed: nothing is high
	for _, f := range fs {
		if f.Confidence == "high" {
			t.Fatal("with a failed hunter, no claim can be high")
		}
	}
	if v := PolicyVerdict(RuleAccountID, "public_value"); v != "real_secret" {
		t.Fatalf("an account id is never a public value here, got %s", v)
	}
	if v := PolicyVerdict("generic-api-key", "test_fixture"); v != "test_fixture" {
		t.Fatalf("policy changed an ordinary verdict: %s", v)
	}
}

func TestEntropyFloorTableCoversEveryLength(t *testing.T) {
	for alpha, min := range map[string]int{"decimal": 16, "hex": 16, "alnum": 12, "base64": 16, "printable": 12} {
		for l := min; l <= 64; l++ {
			if _, ok := entropyFloor[alpha][l]; !ok {
				t.Fatalf("no floor for %s at %d", alpha, l)
			}
		}
	}
}

// A hunter may describe a split hex signing key as private_key: the class
// is the model's description, and the shape check only asks whether the
// line holds something credential-shaped (found at: e2e-lane, the planted
// pull request: both halves of the split key were claimed as private_key,
// correctly, and dropped as "no shape").
func TestShapeIsCheckedByFamily(t *testing.T) {
	d := ParseDiff("diff --git a/k.go b/k.go\n--- a/k.go\n+++ b/k.go\n@@ -0,0 +1,3 @@\n+\tpart1 := \"5b763fa254f83feb3fab\"\n+\tpart2 := \"0a83410be2a9a93800f6\"\n+\tname := \"hello\"\n")
	r := Verify([]Claim{
		{Path: "k.go", Line: 1, Class: "private_key", Reason: "first half of a split signing key", By: "b"},
		{Path: "k.go", Line: 2, Class: "private_key", Reason: "second half", By: "b"},
		{Path: "k.go", Line: 3, Class: "private_key", Reason: "a word", By: "b"},
	}, d)
	if len(r.Candidates) != 2 || r.Dropped["no shape"] != 1 {
		t.Fatalf("candidates %+v dropped %v", r.Candidates, r.Dropped)
	}
}
