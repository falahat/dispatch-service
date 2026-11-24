# Smokescreen with source-network ACL roles. Unknown sources receive the deny-all role.
# The build image matches the Go version pinned by this module.
FROM golang:1.26-bookworm@sha256:4ebd099cae89439fff17af404a9c724079d439b4d92178819318735312ee9eb3 AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go build -o /smokescreen .

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
