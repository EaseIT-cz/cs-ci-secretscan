# The checks CI runs. Gate commits on `make check`.
SHELL := /bin/bash
export GITLEAKS ?= $(CURDIR)/.tools/bin/gitleaks

.PHONY: check tools test lint selfscan

check: lint test selfscan

tools:
	@test -x .tools/bin/gitleaks || scripts/install-gitleaks.sh

lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: files need formatting" >&2; exit 1; }
	go vet ./...

test: tools
	go test -race -count=1 -cover ./...

## selfscan: this repository scanned by its own layer 1, as the working tree
## stands. The scan reads git's index, so it runs on a temporary copy of the
## index with every change staged (GIT_INDEX_FILE): the real index is left
## alone, and a new or modified file is never skipped (found: a published file
## was missed when the scan ran before it was staged).
selfscan: tools
	@idx=$$(mktemp) && trap 'rm -f "$$idx"' EXIT && cp "$$(git rev-parse --git-path index)" "$$idx" && \
	  GIT_INDEX_FILE="$$idx" git add -A && \
	  GIT_INDEX_FILE="$$idx" go run ./cmd/secretscan scan --repo . --gitleaks $(GITLEAKS) --ledgers ledgers
