BINARY_NAME := cert-chain-doctor
BIN_DIR := bin
SRC := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: all build test test-race vet clean install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/cert-chain-doctor

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
