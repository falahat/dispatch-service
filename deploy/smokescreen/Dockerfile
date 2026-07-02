# EgressGuard = smokescreen (adopted), built from source.
FROM golang:1.22-bookworm AS build
RUN go install github.com/stripe/smokescreen@latest

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
