package secretscan

import (
	"strings"
	"testing"
)

const sampleDiff = `diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -10,2 +10,5 @@ module "x" {
   region = "eu-central-1"
+  partner = "359545463725"
+  dashed  = "3595-4546-3725"
+  db = "DBURL"
 }
diff --git a/cmd/app/main.go b/cmd/app/main.go
--- a/cmd/app/main.go
+++ b/cmd/app/main.go
@@ -1,1 +1,3 @@
 package main
+// token TOKEN in a comment
+var x = 1
`

func diffWith(t *testing.T) (string, string) {
	tok := fakeToken(t)
	d := strings.ReplaceAll(sampleDiff, "TOKEN", tok)
	return strings.ReplaceAll(d, "DBURL", strings.TrimPrefix(strings.TrimSuffix(fakeDBURL, `"`), `db = "`)), tok
}

func TestParseDiffMapsNewLines(t *testing.T) {
	d, _ := diffWith(t)
	pd := ParseDiff(d)
	want := map[Loc]bool{{"infra/main.tf", 11}: true, {"infra/main.tf", 12}: true, {"infra/main.tf", 13}: true, {"cmd/app/main.go", 2}: true, {"cmd/app/main.go", 3}: true}
	for loc := range want {
		l, ok := pd.Lines[loc]
		if !ok || !l.Added {
			t.Errorf("%v: not parsed as an added line", loc)
		}
	}
	if l := pd.Lines[Loc{"infra/main.tf", 10}]; l.Added || !strings.Contains(l.Text, "region") {
		t.Errorf("context line wrong: %+v", l)
	}
	if pd.Files != 2 || pd.Added != 5 {
		t.Errorf("Files %d Added %d, want 2 and 5", pd.Files, pd.Added)
	}
}

func TestMaskBlanksFindingsAndAccountIDsAndProvesIt(t *testing.T) {
	d, tok := diffWith(t)
	m, err := Mask(MaskOptions{Diff: d, Gitleaks: gitleaksPath(t), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{tok, tok[4:16], "359545463725", "3595-4546-3725", "Qxve"} {
		if strings.Contains(m.Diff, leaked) {
			t.Errorf("masked diff still holds %q", leaked)
		}
	}
	for _, want := range []string{"[REDACTED:account-id]", "[REDACTED:", `region = "eu-central-1"`, "var x = 1"} {
		if !strings.Contains(m.Diff, want) {
			t.Errorf("masked diff lacks %q:\n%s", want, m.Diff)
		}
	}
	if m.Rounds < 1 || m.Masked == 0 {
		t.Errorf("Rounds %d Masked %d", m.Rounds, m.Masked)
	}
	// The proof: a rescan of the masked diff finds nothing.
	if fs, err := rescan(m.Diff, gitleaksPath(t), t.TempDir(), Checker{}, ""); err != nil || len(fs) != 0 {
		t.Fatalf("rescan of the masked diff: %v %v", fs, err)
	}
}

func TestMaskLinesKeepsLineCount(t *testing.T) {
	d, _ := diffWith(t)
	m, err := Mask(MaskOptions{Diff: d, Gitleaks: gitleaksPath(t), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(m.Diff, "\n") != strings.Count(d, "\n") {
		t.Fatal("the mask changed the number of lines; line numbers would no longer match")
	}
}

func TestMaskToken(t *testing.T) {
	line := `+  db_password = "s3cr3t-Value_1" # note`
	got := maskSpan(line, 20, 22, "generic-api-key")
	if strings.Contains(got, "s3cr3t") || !strings.Contains(got, "db_password") || !strings.Contains(got, "# note") {
		t.Fatalf("maskSpan = %q", got)
	}
}
