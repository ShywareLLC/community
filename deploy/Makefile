.PHONY: help build test lint docker-validator docker-api zk-setup

REPO_ROOT := $(shell git rev-parse --show-toplevel)

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all shyvoting binaries
	cd $(REPO_ROOT) && go build -o bin/shyvoting-abci       ./shyware/shyvoting/cmd/shyvoting-abci/
	cd $(REPO_ROOT) && go build -o bin/shyvoting-api        ./shyware/shyvoting/cmd/shyvoting-api/
	cd $(REPO_ROOT) && go build -o bin/shyvoting-verify     ./shyware/shyvoting/cmd/shyvoting-verify/
	cd $(REPO_ROOT) && go build -o bin/shyvoting-affinities ./shyware/shyvoting/cmd/shyvoting-affinities/
	@echo "Binaries written to $(REPO_ROOT)/bin/"

test: ## Run unit tests across shyware workspace
	cd $(REPO_ROOT)/shyware && go test -v -race ./...
	cd $(REPO_ROOT)/shyware/shyvoting && go test -v -race ./...

lint: ## Run golangci-lint
	cd $(REPO_ROOT)/shyware && golangci-lint run --timeout=5m
	cd $(REPO_ROOT)/shyware/shyvoting && golangci-lint run --timeout=5m

docker-validator: ## Build the shared validator Docker image (build context = repo root)
	docker build \
	  -t shyvoting-validator:latest \
	  -f $(REPO_ROOT)/shyware/deploy/docker/Dockerfile.validator \
	  $(REPO_ROOT)

docker-api: ## Build the shared API Docker image (build context = repo root)
	docker build \
	  -t shyvoting-api:latest \
	  -f $(REPO_ROOT)/shyware/deploy/docker/Dockerfile.api \
	  $(REPO_ROOT)

zk-setup: ## Run one-time Groth16 trusted setup (dev only — single-party)
	@echo "WARNING: single-party setup is dev-only. Production requires a multi-party ceremony."
	cd $(REPO_ROOT) && go run ./shyware/shyvoting/cmd/zk-setup \
	  --pk $(REPO_ROOT)/nullifier_pk.bin \
	  --vk $(REPO_ROOT)/nullifier_vk.bin
