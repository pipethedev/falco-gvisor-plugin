# Falco with the gvisor plugin, rules and example configs.
ARG FALCO_IMAGE=falcosecurity/falco:0.45.0@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6
ARG GO_IMAGE=golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
RUN CGO_ENABLED=1 go build -trimpath -buildmode=c-shared \
      -ldflags "-s -w -X github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor.PluginVersion=${VERSION#v}" \
      -o /out/libgvisor.so ./cmd/plugin

FROM ${FALCO_IMAGE}
COPY --from=build /out/libgvisor.so /usr/share/falco/plugins/libgvisor.so
COPY rules/gvisor_rules.yaml /etc/falco/rules.d/gvisor_rules.yaml
COPY deploy/falco.rules.d/gvisor_host_exceptions.yaml /etc/falco/rules.d/gvisor_host_exceptions.yaml
COPY deploy/falco.config.d/gvisor.yaml /etc/falco/config.d/gvisor.yaml
COPY deploy/gvisor-session.json deploy/gvisor-pod-init.json deploy/gvisor-session-full.json deploy/pod-init-full.json /etc/falco/
