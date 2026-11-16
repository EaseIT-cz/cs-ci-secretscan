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

## selfscan: this repository scanned by its own layer 1.
selfscan: tools
	go run ./cmd/secretscan scan --repo . --gitleaks $(GITLEAKS) --ledgers ledgers
