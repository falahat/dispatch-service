# EgressGuard = stripe/smokescreen embedded with a static "worker" role (main.go —
# the vendor's RoleFromRequest hook; the stock binary can only role clients via TLS
# client certs and hard-denies everything else). Pinned via go.mod/go.sum. The build
# image must satisfy the smokescreen pin's `go 1.25` (GOTOOLCHAIN=local — no download).
FROM golang:1.25-bookworm@sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38 AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go build -o /smokescreen .

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
