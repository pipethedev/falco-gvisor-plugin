NAME := gvisor
OUTPUT := lib$(NAME).so
ARCHES := amd64 arm64
GO ?= go
GOLANGCI_VERSION ?= v2.15.0
GOLANGCI_LINT ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
BUILDER_IMAGE ?= golang:1.27-bookworm
FALCO_IMAGE ?= falcosecurity/falco:0.45.0
TEST_IMAGE ?= alpine:3.20
HOST_ARCH ?= $(shell $(GO) env GOARCH)
DIST := dist
VERSION ?= 0.1.0
LDFLAGS := -s -w -X github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor.PluginVersion=$(VERSION:v%=%)

.PHONY: all build build-linux $(addprefix build-linux-,$(ARCHES)) test test-linux test-integration test-gvisor rules-test lint generate rules-tarball plugin-tarballs image clean

all: build

build:
	CGO_ENABLED=1 $(GO) build -trimpath -buildmode=c-shared -ldflags "$(LDFLAGS)" -o $(OUTPUT) ./cmd/plugin

build-linux: $(addprefix build-linux-,$(ARCHES))

$(addprefix build-linux-,$(ARCHES)): build-linux-%:
	mkdir -p $(DIST)/$*
	docker run --rm --platform linux/$* -v $(CURDIR):/src -w /src \
		-e GOFLAGS=-buildvcs=false $(BUILDER_IMAGE) \
		sh -c 'CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -ldflags "$(LDFLAGS)" -o $(DIST)/$*/$(OUTPUT) ./cmd/plugin && \
		CGO_ENABLED=0 go build -trimpath -o $(DIST)/$*/replay ./tools/replay'

test:
	$(GO) test -race -count=1 ./...

test-linux:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(HOST_ARCH) $(GO) test -c -o $(DIST)/gvisor.test ./pkg/gvisor
	docker run --rm -v $(CURDIR)/$(DIST):/t --entrypoint /t/gvisor.test $(TEST_IMAGE) -test.count=1

test-integration: image
	IMAGE=falco-gvisor:$(VERSION) ./test/integration/run.sh

test-gvisor: image
	IMAGE=falco-gvisor:$(VERSION) ./test/gvisor/run.sh

rules-test: build-linux-$(HOST_ARCH)
	FALCO_IMAGE=$(FALCO_IMAGE) PLUGIN_DIR=$(CURDIR)/$(DIST)/$(HOST_ARCH) ./rules/tests/run.sh

lint:
	$(GOLANGCI_LINT) run ./...

generate:
	$(GO) generate ./...

rules-tarball:
	mkdir -p $(DIST)
	COPYFILE_DISABLE=1 tar -czf $(DIST)/$(NAME)-rules-$(VERSION).tar.gz -C rules gvisor_rules.yaml

plugin-tarballs: build-linux
	COPYFILE_DISABLE=1 tar -czf $(DIST)/$(NAME)-$(VERSION)-linux-x86_64.tar.gz -C $(DIST)/amd64 $(OUTPUT)
	COPYFILE_DISABLE=1 tar -czf $(DIST)/$(NAME)-$(VERSION)-linux-aarch64.tar.gz -C $(DIST)/arm64 $(OUTPUT)

image:
	docker build --build-arg VERSION=$(VERSION) -t falco-gvisor:$(VERSION) -f Dockerfile .

clean:
	rm -rf $(OUTPUT) lib$(NAME).h $(DIST)
