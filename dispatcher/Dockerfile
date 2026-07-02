# Dispatcher image — static, cgo-free Go binary on a distroless base.
# Build context is the repo root.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/dispatcherd ./dispatcher/cmd/dispatcherd

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/dispatcherd /dispatcherd
# app surface (UDS on a shared volume) + runner surface (fronted by the PEP).
ENTRYPOINT ["/dispatcherd"]
CMD ["-config", "/etc/dispatch/plane.toml"]
