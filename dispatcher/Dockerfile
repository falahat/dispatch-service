# Dispatcher image — static, cgo-free Go binary on a distroless base.
# Build context is the repo root.
FROM golang:1.26@sha256:6ef03c9474cb3b3ba3f18e31aa2938ee419e58f164ce5e012b28e61c039b1aa6 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/dispatcherd ./dispatcher/cmd/dispatcherd

FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=build /out/dispatcherd /dispatcherd
# app surface (UDS on a shared volume) + runner surface (fronted by the PEP).
ENTRYPOINT ["/dispatcherd"]
CMD ["-config", "/etc/dispatch/plane.toml"]
