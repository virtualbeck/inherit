GO      ?= go
PKG     := github.com/virtualbeck/inherit
BIN     := inherit

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build dev dist test integration vet fmt lint coverage schema

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/inherit
	@echo "built bin/$(BIN)  ($(VERSION))"

dev:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN)-linux-amd64 ./cmd/inherit

dist:
	@mkdir -p dist
	@$(foreach p,$(PLATFORMS), \
		os=$(word 1,$(subst /, ,$(p))); arch=$(word 2,$(subst /, ,$(p))); \
		ext=$(if $(filter windows,$(word 1,$(subst /, ,$(p)))),.exe,); \
		out=dist/$(BIN)_$(VERSION)_$${os}_$${arch}$${ext}; \
		echo "-> $${out}"; \
		CGO_ENABLED=0 GOOS=$${os} GOARCH=$${arch} $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $${out} ./cmd/inherit || exit 1; \
	)
	@cd dist && sha256sum inherit_* > SHA256SUMS

test:
	$(GO) test ./...

# real tofu/terraform init + validate (+ the fast-import safety gate) against
# generated projects; needs tofu or terraform on PATH and network access for
# the provider download. No AWS credentials.
integration:
	INHERIT_INTEGRATION=1 $(GO) test ./internal/emit/ ./internal/cli/

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

lint:
	golangci-lint run ./...

# regenerates docs/COVERAGE.md from the hydrator registry
coverage:
	$(GO) run ./tfschema/cmd/coverage -md > docs/COVERAGE.md

# re-bundles the latest hashicorp/aws 6.x provider schema (needs tofu/terraform)
schema:
	$(GO) run ./tfschema/cmd/genschema
