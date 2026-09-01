# Runner image — static, cgo-free Go binary. Drives a paired compute container
# over the invoke protocol; holds a credential but no domain logic.
# Build context is the repo root.
FROM golang:1.27@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/runner ./runner/cmd/runner

FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
COPY --from=build /out/runner /runner
ENTRYPOINT ["/runner"]
CMD ["run"]
