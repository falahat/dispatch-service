# PEP + signer image (Rust). The PEP fronts both tailnet surfaces; the signer
# mints credentials (CLI, out of band). Build context is the auth/ directory.
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
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
