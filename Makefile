BINARY_NAME=hydraflow
SUB_BINARY=hydraflow-sub
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-sub test lint clean install

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/hydraflow/

build-sub:
	go build -o bin/$(SUB_BINARY) ./tools/sub-server.go

build-all: build build-sub

test:
	go test -v -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin/

install: build build-sub
	cp bin/$(BINARY_NAME) /usr/local/bin/
	cp bin/$(SUB_BINARY) /usr/local/bin/
