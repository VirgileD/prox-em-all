VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
STATICCHECK_VERSION := v0.8.1
GOVULNCHECK_VERSION := v1.8.0

.PHONY: help build test lint integration-test image clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the prox-em-all binary
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o prox-em-all ./cmd/prox-em-all

test: ## Run the unit tests
	go test -race ./...

lint: ## Check formatting, then run go vet, staticcheck and govulncheck
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "files above need gofmt"; exit 1; }
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

integration-test: ## Run the end-to-end test with docker compose (root not needed)
	test/integration/run.sh

image: ## Build the prox-em-all docker image
	docker build --build-arg VERSION=$(VERSION) -t prox-em-all:$(VERSION) -t prox-em-all:latest .

clean: ## Remove the built binary
	rm -f prox-em-all
