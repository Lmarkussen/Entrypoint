BIN_DIR := bin
BINARY := $(BIN_DIR)/entrypoint
CACHE_DIR := .cache/go-build

.PHONY: build
build:
	mkdir -p $(BIN_DIR) $(CACHE_DIR)
	GOCACHE=$(CURDIR)/$(CACHE_DIR) go build -o $(BINARY) ./cmd/entrypoint
