# Smokescreen with source-network ACL roles. Unknown sources receive the deny-all role.
# The build image matches the Go version pinned by this module.
FROM golang:1.26-bookworm@sha256:4ebd099cae89439fff17af404a9c724079d439b4d92178819318735312ee9eb3 AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go build -o /smokescreen .

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /smokescreen /usr/local/bin/smokescreen
ENTRYPOINT ["smokescreen"]
