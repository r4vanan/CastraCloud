.PHONY: build test vet run-api run-waf run-cspm web-dev web-build tidy

GO ?= go
BIN := bin

build:
	$(GO) build -o $(BIN)/api ./cmd/api
	$(GO) build -o $(BIN)/waf ./cmd/waf
	$(GO) build -o $(BIN)/cspm ./cmd/cspm

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

run-api:
	$(GO) run ./cmd/api

run-waf:
	$(GO) run ./cmd/waf

run-cspm:
	$(GO) run ./cmd/cspm

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build
