# Dispatcher image — static, cgo-free Go binary on a distroless base.
# Build context is the repo root.
FROM golang:1.26@sha256:6ef03c9474cb3b3ba3f18e31aa2938ee419e58f164ce5e012b28e61c039b1aa6 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/dispatcherd ./dispatcher/cmd/dispatcherd

FROM gcr.io/distroless/static:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build /out/dispatcherd /dispatcherd
# app surface (UDS on a shared volume) + runner surface (fronted by the PEP).
ENTRYPOINT ["/dispatcherd"]
CMD ["-config", "/etc/dispatch/plane.toml"]
