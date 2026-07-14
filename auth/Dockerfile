# PEP + signer image (Rust). The PEP fronts both tailnet surfaces; the signer
# mints credentials (CLI, out of band). Build context is the auth/ directory.
FROM rust:1.97-bookworm@sha256:606f3248aa86ce49e0b98d9e0bbffde042adeb18982320f97bcc218615de1c99 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin pep --bin signer

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN useradd -r -u 10001 pep
COPY --from=build /src/target/release/pep /usr/local/bin/pep
COPY --from=build /src/target/release/signer /usr/local/bin/signer
USER pep
ENTRYPOINT ["pep"]
