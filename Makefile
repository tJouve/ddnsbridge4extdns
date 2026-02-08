.PHONY: build test clean run docker-build docker-push deploy help

# Variables
BINARY_NAME=ddnstoextdns
DOCKER_IMAGE?=ddnstoextdns
DOCKER_TAG?=latest
NAMESPACE?=ddnstoextdns

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) ./cmd/server

test: ## Run tests
	@echo "Running tests..."
	go test ./... -v -cover

test-short: ## Run tests without verbose output
	@echo "Running tests..."
	go test ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	go clean

run: ## Run the server locally (requires environment variables)
	@echo "Running $(BINARY_NAME)..."
	go run ./cmd/server

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

lint: fmt vet ## Run formatters and linters

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-push: ## Push Docker image to registry
	@echo "Pushing Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deploy/kubernetes/deployment.yaml

undeploy: ## Remove from Kubernetes
	@echo "Removing from Kubernetes..."
	kubectl delete -f deploy/kubernetes/deployment.yaml

logs: ## Show logs from deployed pods
	@echo "Showing logs..."
	kubectl logs -n $(NAMESPACE) -l app=ddnstoextdns -f

status: ## Show deployment status
	@echo "Deployment status:"
	kubectl get all -n $(NAMESPACE)
	@echo ""
	@echo "DNSEndpoints:"
	kubectl get dnsendpoint -n default

install-deps: ## Install Go dependencies
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

generate-secret: ## Generate a random TSIG secret
	@echo "Generating random TSIG secret:"
	@openssl rand -base64 32

.DEFAULT_GOAL := help
