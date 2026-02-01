BINARY_NAME=hydraflow
SERVER_BINARY=hf-server
SUB_BINARY=hydraflow-sub
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-server build-sub test lint clean install

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/hydraflow/

build-server:
	go build $(LDFLAGS) -o bin/$(SERVER_BINARY) ./cmd/hf-server/

build-sub:
	go build -o bin/$(SUB_BINARY) ./tools/sub-server.go

build-all: build build-server build-sub

test:
	go test -v -race -count=1 ./...

test-short:
	go test -short -race ./...

test-integration:
	go test -v -tags=integration -race ./...

test-probe:
	go test -v -tags=probe -race ./discovery/...

test-coverage:
	go test -coverprofile=coverage.out -race ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w .

vet:
	go vet ./...

clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

install: build
	cp bin/$(BINARY_NAME) /usr/local/bin/

docker-build:
	docker build -t hydraflow:$(VERSION) .

docker-run:
	docker run -d --name hydraflow --network host \
		-v /etc/hydraflow:/etc/hydraflow \
		hydraflow:$(VERSION)

proto:
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

help:
	@echo "Available targets:"
	@echo "  build          - Build client binary"
	@echo "  build-server   - Build server binary"
	@echo "  build-probe    - Build probe tool"
	@echo "  build-all      - Build all binaries"
	@echo "  test           - Run all tests"
	@echo "  test-short     - Run short tests"
	@echo "  test-coverage  - Generate coverage report"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  clean          - Remove build artifacts"
	@echo "  docker-build   - Build Docker image"
	@echo "  install        - Install to /usr/local/bin"
