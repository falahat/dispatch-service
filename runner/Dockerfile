# Runner image — static, cgo-free Go binary. Drives a paired compute container
# over the invoke protocol; holds a credential but no domain logic.
# Build context is the repo root.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/runner ./runner/cmd/runner

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/runner /runner
ENTRYPOINT ["/runner"]
CMD ["run"]
