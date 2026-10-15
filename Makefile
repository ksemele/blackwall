BIN_DIR := bin
PKG     := ./...
GOBIN   := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

.PHONY: build install test lint build-linux smoke clean

build:
	go build -o $(BIN_DIR)/blackwall ./cmd/blackwall

# Installs blackwall and a short alias `b` (symlink), unless `b` is taken.
install:
	go install ./cmd/blackwall
	@if [ "$$(readlink "$(GOBIN)/b" 2>/dev/null)" = blackwall ] || ! command -v b >/dev/null 2>&1; then \
		ln -sf blackwall "$(GOBIN)/b" && echo "alias: $(GOBIN)/b -> blackwall"; \
	else \
		echo "alias: skipped, b is already $$(command -v b)"; \
	fi

test:
	go test -race $(PKG)

lint:
	golangci-lint run

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/blackwall-linux-amd64 ./cmd/blackwall

smoke:
	scripts/smoke.sh

clean:
	rm -rf $(BIN_DIR)
