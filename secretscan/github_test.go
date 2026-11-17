package secretscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUpsertCreatesThenUpdates(t *testing.T) {
	var comments []map[string]any
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		methods = append(methods, r.Method)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		switch {
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(comments)
		case r.Method == http.MethodPost:
			comments = append(comments, map[string]any{"id": 7, "body": body["body"]})
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/comments/7"):
			comments[0]["body"] = body["body"]
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	g := &GitHub{API: srv.URL, Repo: "o/r", Token: "gh-test"}
	ctx := context.Background()
	if err := g.Upsert(ctx, 5, CommentMarker+"\nfirst"); err != nil {
		t.Fatal(err)
	}
	if err := g.Upsert(ctx, 5, CommentMarker+"\nsecond"); err != nil {
		t.Fatal(err)
	}
	if len(comments) != 1 || !strings.HasSuffix(comments[0]["body"].(string), "second") {
		t.Fatalf("comments %v", comments)
	}
	if strings.Join(methods, ",") != "GET,POST,GET,PATCH" {
		t.Fatalf("calls %v", methods)
	}
	if err := (&GitHub{API: srv.URL, Repo: "o/r", Token: "bad"}).Upsert(ctx, 5, "x"); err == nil {
		t.Fatal("a refused token must be an error")
	}
}

func TestCompletionCountsReviewOutcomes(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 1, "updated_at": now.Add(-time.Hour)},
				{"number": 2, "updated_at": now.Add(-2 * time.Hour)},
				{"number": 3, "updated_at": now.Add(-3 * time.Hour)},
				{"number": 4, "updated_at": now.Add(-30 * 24 * time.Hour)},
			})
		case strings.Contains(r.URL.Path, "/issues/1/"):
			json.NewEncoder(w).Encode([]map[string]string{{"body": CommentMarker + "\nExamined 3 file(s)"}})
		case strings.Contains(r.URL.Path, "/issues/2/"):
			json.NewEncoder(w).Encode([]map[string]string{{"body": CommentMarker + "\n**Layer 2 did not complete:** both hunters failed. Layer 1 is unaffected."}})
		default:
			json.NewEncoder(w).Encode([]map[string]string{})
		}
	}))
	defer srv.Close()
	g := &GitHub{API: srv.URL, Repo: "o/r", Token: "t"}
	r, err := g.Completion(context.Background(), now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.PRs != 3 || r.Completed != 1 || r.NoComment != 1 || r.Reasons["both hunters failed"] != 1 {
		t.Fatalf("report %+v", r)
	}
}

// A page of full pull-request objects is large (found at: e2e-lane, the
// first weekly self-test: 100 per page passed the 1 MB read cap and the
// JSON was cut: "unexpected end of JSON input"). Pages are smaller now, and
// the GitHub client's cap fits them.
func TestCompletionReadsLargePages(t *testing.T) {
	now := time.Now()
	pad := strings.Repeat("x", 60000) // a PR object's body, labels and links
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pulls") {
			var prs []map[string]any
			if r.URL.Query().Get("page") == "1" {
				for i := 1; i <= githubPage; i++ {
					prs = append(prs, map[string]any{"number": i, "updated_at": now.Add(-time.Hour), "body": pad})
				}
			}
			json.NewEncoder(w).Encode(prs)
			return
		}
		json.NewEncoder(w).Encode([]map[string]string{{"body": CommentMarker + "\nExamined 1 file(s)"}})
	}))
	defer srv.Close()
	r, err := (&GitHub{API: srv.URL, Repo: "o/r", Token: "t"}).Completion(context.Background(), now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.PRs != githubPage || r.Completed != githubPage {
		t.Fatalf("report %+v", r)
	}
}

// A response over the cap is an error that names the cap, never cut JSON.
func TestGitHubResponseOverTheCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"body":"` + strings.Repeat("x", githubMaxResponse) + `"}]`))
	}))
	defer srv.Close()
	_, err := (&GitHub{API: srv.URL, Repo: "o/r", Token: "t"}).Completion(context.Background(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err %v", err)
	}
}
