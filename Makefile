GO ?= go
# Images are Linux; build for the cluster nodes regardless of the host OS.
GOOS ?= linux
GOARCH ?= amd64
CA_BUNDLE ?= $(firstword $(wildcard /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem))
export GO111MODULE = on
IMAGE ?= periscope:local
.PHONY: test build image package
test:
	$(GO) test -race ./...
	$(GO) vet ./...
build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/linux-$(GOARCH)/periscope ./cmd/periscope
	@test -n "$(CA_BUNDLE)" || { echo 'no CA bundle found; set CA_BUNDLE' >&2; exit 1; }
	cp $(CA_BUNDLE) dist/ca-certificates.crt
image: build
	docker build --network=none --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE) .
	docker save -o dist/periscope-images.tar $(IMAGE)
package:
	mkdir -p dist
	helm lint charts/periscope -f tests/e2e/suite/values-openai.yaml
	helm package charts/periscope -d dist
