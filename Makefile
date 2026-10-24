BINARY_NAME := cert-chain-doctor
BIN_DIR := bin
SRC := $(shell find . -name '*.go' -not -path './vendor/*')

VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "dev")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build test test-race vet clean install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/cert-chain-doctor

test:
	go test -v ./...

test-race:
	go test -race -v ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN_DIR)

install:
	CGO_ENABLED=0 go install ./cmd/cert-chain-doctor
