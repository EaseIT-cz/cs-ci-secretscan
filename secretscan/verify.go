package secretscan

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Claim is one model hunter's claim: a path, a new-file line, a class and
// a reason in words.
type Claim struct {
	Path   string
	Line   int
	Class  string
	Reason string
	By     string // "a" or "b"
}

// Candidate is a claim that survived layer 3, merged with the other
// hunter's when they agree, ready for the adjudicator.
type Candidate struct {
	ID         string
	Path       string
	Line       int
	Class      string
	FoundBy    string   // both, hunter_a, hunter_b
	Reasons    []string // after the reason checks
	MaskedText string   // the claimed line, masked
}

// VerifyResult is what survived and why the rest did not.
type VerifyResult struct {
	Candidates []Candidate
	Dropped    map[string]int
}

var families = map[string]string{
	"token": "credential", "api_key": "credential", "password": "credential", "private_key": "credential",
	"connection_string": "credential", "encoded_blob": "credential",
	"cloud_account_id": "identifier", "internal_host": "identifier", "email": "identifier",
	"other": "other",
}

// Verify checks every claim against the diff (docs/design.md §5): its
// path is in the diff, its line is an added line that was not masked, and
// the line has the shape of the class. d is the unmasked diff after
// masking was applied to it in memory: a line holding a [REDACTED:...]
// token was masked, so it is layer 1's and already reported.
func Verify(claims []Claim, d ParsedDiff) VerifyResult {
	r := VerifyResult{Dropped: map[string]int{}}
	paths := map[string]bool{}
	for loc := range d.Lines {
		paths[loc.Path] = true
	}
	type kept struct {
		c   Claim
		txt string
	}
	var ok []kept
	for _, c := range claims {
		l, found := d.Lines[Loc{c.Path, c.Line}]
		switch {
		case families[c.Class] == "":
			r.Dropped["unknown class"]++
		case !paths[c.Path]:
			r.Dropped["no such path"]++
		case !found || !l.Added:
			r.Dropped["not an added line"]++
		case alreadyRed.MatchString(l.Text):
			r.Dropped["masked line"]++
		case c.Class != "other" && !hasFamilyShape(c.Class, l.Text):
			r.Dropped["no shape"]++
		default:
			ok = append(ok, kept{c, l.Text})
		}
	}
	// Merge claims on one secret: same path, lines within 2, same family.
	used := make([]bool, len(ok))
	var cands []Candidate
	for i, a := range ok {
		if used[i] {
			continue
		}
		used[i] = true
		cand := Candidate{Path: a.c.Path, Line: a.c.Line, Class: a.c.Class, MaskedText: a.txt}
		by := map[string]bool{a.c.By: true}
		reasons := []Claim{a.c}
		for j := i + 1; j < len(ok); j++ {
			b := ok[j]
			// Any hunter's claim within 2 lines in the same family is the same
			// secret: the other hunter's agrees, the same hunter's is its
			// other half (a key split across adjacent lines).
			if used[j] || b.c.Path != a.c.Path || abs(b.c.Line-a.c.Line) > 2 ||
				families[b.c.Class] != families[a.c.Class] {
				continue
			}
			used[j] = true
			by[b.c.By] = true
			reasons = append(reasons, b.c)
		}
		switch {
		case by["a"] && by["b"]:
			cand.FoundBy = "both"
		case by["a"]:
			cand.FoundBy = "hunter_a"
		default:
			cand.FoundBy = "hunter_b"
		}
		if cand.Class == "other" && cand.FoundBy != "both" {
			r.Dropped["other needs both"]++
			continue
		}
		for _, rc := range reasons {
			txt := d.Lines[Loc{rc.Path, rc.Line}].Text
			if reasonSurvives(rc.Reason, txt) {
				cand.Reasons = append(cand.Reasons, rc.Reason)
			} else {
				cand.Reasons = append(cand.Reasons, "(reason withheld)")
			}
		}
		cands = append(cands, cand)
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Path != cands[j].Path {
			return cands[i].Path < cands[j].Path
		}
		return cands[i].Line < cands[j].Line
	})
	for i := range cands {
		cands[i].ID = fmt.Sprintf("c%02d", i+1)
	}
	r.Candidates = cands
	return r
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

var (
	connString = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S*@`)
	b64Run     = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexRun     = regexp.MustCompile(`[0-9a-fA-F]{24,}`)
	pctRun     = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}){12,}`)
	b64Body    = regexp.MustCompile(`[A-Za-z0-9+/]{64,}`)
	hostRe     = regexp.MustCompile(`\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// hasFamilyShape reports whether a line has the shape of any class in the
// claim's family. A class is the model's description (a split hex signing
// key is fairly called private_key); the check asks only whether the line
// holds something of the family's shape (found at e2e-lane).
func hasFamilyShape(class, line string) bool {
	fam := families[class]
	for c, f := range families {
		if f == fam && c != "other" && hasShape(c, line) {
			return true
		}
	}
	return false
}

// hasShape reports whether a line has the shape of a class.
func hasShape(class, line string) bool {
	switch class {
	case "cloud_account_id":
		return accountRun.MatchString(line)
	case "connection_string":
		return connString.MatchString(line)
	case "encoded_blob":
		return b64Run.MatchString(line) || hexRun.MatchString(line) || pctRun.MatchString(line)
	case "token", "api_key", "password":
		for _, run := range runs(line) {
			if highEntropy(run) {
				return true
			}
		}
		return false
	case "private_key":
		return pemKey.MatchString(line) || b64Body.MatchString(line)
	case "internal_host":
		return hostRe.MatchString(line)
	case "email":
		return emailRe.MatchString(line)
	}
	return false
}

// runs splits a line into candidate values at whitespace, quotes and the
// punctuation that separates values in code.
func runs(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		return r <= ' ' || r > '~' || strings.ContainsRune("\"'`=,;()[]{}<>", r)
	})
}

var alphabetOrder = []struct {
	name string
	ok   func(byte) bool
	min  int
}{
	{"decimal", func(c byte) bool { return c >= '0' && c <= '9' }, 16},
	{"hex", func(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }, 16},
	{"alnum", func(c byte) bool { return isAlnum(c) || c == '_' || c == '-' }, 12},
	{"base64", func(c byte) bool { return isAlnum(c) || strings.IndexByte("+/=_-", c) >= 0 }, 16},
	{"printable", func(c byte) bool { return c >= 33 && c <= 126 }, 12},
}

// highEntropy reports whether a run reaches the entropy floor for the
// first alphabet that holds it, at its length (the 64 cell for longer).
func highEntropy(run string) bool {
	for _, a := range alphabetOrder {
		holds := true
		for i := 0; i < len(run); i++ {
			if !a.ok(run[i]) {
				holds = false
				break
			}
		}
		if !holds {
			continue
		}
		if len(run) < a.min {
			return false
		}
		l := len(run)
		if l > 64 {
			l = 64
		}
		return int(math.Floor(shannon(run)*1000)) >= entropyFloor[a.name][l]
	}
	return false
}

func shannon(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var reasonForbidden = []string{"@", "`", "<", ">", "|", "[", "]", "://", "//", "\n", "\r"}

// reasonSurvives applies the reason checks: no forbidden character, no
// leading "-" or "#", and no 8-character window of the line's value-shaped
// runs. A plain lowercase word shared with the code ("password") is not
// an echo, so only runs that are not plain lowercase words are compared.
func reasonSurvives(reason, line string) bool {
	for _, f := range reasonForbidden {
		if strings.Contains(reason, f) {
			return false
		}
	}
	if t := strings.TrimSpace(reason); strings.HasPrefix(t, "-") || strings.HasPrefix(t, "#") {
		return false
	}
	for _, run := range runs(line) {
		if len(run) < 8 || isPlainWord(run) {
			continue
		}
		for i := 0; i+8 <= len(run); i++ {
			if strings.Contains(reason, run[i:i+8]) {
				return false
			}
		}
	}
	return true
}

func isPlainWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// Finding2 is a confirmed layer 2 finding, as reported.
type Finding2 struct {
	Candidate
	Confidence string // high or medium
}

// Adjudicate applies the adjudicator's decisions: a confirmed claim found
// by both hunters is high, by one medium; a rejected or undecided claim is
// dropped and counted. When a hunter failed, nothing is high.
func Adjudicate(cands []Candidate, decisions map[string]string, hunterFailed bool) ([]Finding2, map[string]int) {
	dropped := map[string]int{}
	var out []Finding2
	for _, c := range cands {
		switch decisions[c.ID] {
		case "confirm":
			conf := "medium"
			if c.FoundBy == "both" && !hunterFailed {
				conf = "high"
			}
			out = append(out, Finding2{Candidate: c, Confidence: conf})
		case "reject":
			dropped["rejected"]++
		default:
			dropped["undecided"]++
		}
	}
	return out, dropped
}

// PolicyVerdict applies the repository policy in code: a layer 1 finding of
// an account id or a URL password stays real_secret whatever a model said.
func PolicyVerdict(rule, verdict string) string {
	if rule == RuleAccountID || rule == RuleURLPassword {
		return "real_secret"
	}
	return verdict
}
