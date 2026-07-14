# PEP + signer image (Rust). The PEP fronts both tailnet surfaces; the signer
# mints credentials (CLI, out of band). Build context is the auth/ directory.
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin pep --bin signer

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN useradd -r -u 10001 pep
COPY --from=build /src/target/release/pep /usr/local/bin/pep
COPY --from=build /src/target/release/signer /usr/local/bin/signer
USER pep
ENTRYPOINT ["pep"]
