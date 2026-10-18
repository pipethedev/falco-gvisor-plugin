NAME := gvisor
OUTPUT := lib$(NAME).so
ARCHES := amd64 arm64
GO ?= go
GOLANGCI_VERSION ?= v2.6.2
LINT ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
BUILDER_IMAGE ?= golang:1.27-bookworm
DIST := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor.PluginVersion=$(VERSION:v%=%)

.PHONY: all build build-linux $(addprefix build-linux-,$(ARCHES)) test test-integration lint generate rules-tarball image clean

all: build

build:
	CGO_ENABLED=1 $(GO) build -trimpath -buildmode=c-shared -ldflags "$(LDFLAGS)" -o $(OUTPUT) ./cmd/plugin

build-linux: $(addprefix build-linux-,$(ARCHES))

build-linux-%:
	mkdir -p $(DIST)/$*
	docker run --rm --platform linux/$* -v $(CURDIR):/src -w /src \
		-e GOFLAGS=-buildvcs=false $(BUILDER_IMAGE) \
		sh -c 'CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -ldflags "$(LDFLAGS)" -o $(DIST)/$*/$(OUTPUT) ./cmd/plugin'

test:
	$(GO) test -race -count=1 ./...

test-integration:
	sudo -E ./test/integration/run.sh

lint:
	$(LINT) run ./...

generate:
	$(GO) generate ./...

rules-tarball:
	mkdir -p $(DIST)
	tar -czf $(DIST)/$(NAME)-rules-$(VERSION).tar.gz -C rules gvisor_rules.yaml

image:
	docker build -t falco-gvisor:$(VERSION) -f Dockerfile .

clean:
	rm -rf $(OUTPUT) lib$(NAME).h $(DIST)
