package secretscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
