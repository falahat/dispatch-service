# Smokescreen with source-network ACL roles. Unknown sources receive the deny-all role.
# The build image matches the Go version pinned by this module.
FROM golang:1.26-bookworm@sha256:349ad04971da5f200a537641ae2c70774a592ca21fad4b513b65f813f546781a AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go build -o /smokescreen .

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
