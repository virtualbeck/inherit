GO      ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
PKG     := github.com/virtualbeck/inherit-core
BIN     := inherit

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build dev test vet fmt lint coverage

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/inherit
	@echo "built bin/$(BIN)  ($(VERSION))"

dev:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN)-linux-amd64 ./cmd/inherit

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

lint:
	golangci-lint run ./...

# regenerates the vendored provider schema breakdown
coverage:
	$(GO) run ./tfschema/cmd/coverage -md > docs/COVERAGE.md
