#!/usr/bin/env bash
# Bootstrap the plane's trust material: the issuer key, the PEP's root public
# key (.env), and one enrolled runner credential (deploy/cred/cred.json).
# Pairing is done HERE, out of band — there is no network enrollment endpoint.
#
# Needs the host toolchains (cargo, go) to build the signer + runner tools.
# Re-runnable: it preserves an existing secrets.json (no device re-enrollment).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
mkdir -p deploy/secrets deploy/cred

echo "== building signer + runner tools =="
cargo build --release --manifest-path auth/Cargo.toml --bin signer >/dev/null
go build -o deploy/secrets/runner-tool ./runner/cmd/runner

SIGNER=(auth/target/release/signer -secrets deploy/secrets/secrets.json)

echo "== root public key -> .env =="
ROOT_PUB="$("${SIGNER[@]}" pubkey)"
# Upsert, don't clobber: preserve any other vars already in .env (matches plane-enroll.sh).
touch .env
grep -v '^PEP_ROOT_PUBKEY=' .env > .env.tmp || true
echo "PEP_ROOT_PUBKEY=$ROOT_PUB" >> .env.tmp
mv .env.tmp .env
echo "   PEP_ROOT_PUBKEY=$ROOT_PUB"

LANES="${1:-embed}"
RIGHTS="hello,lease,heartbeat,complete,fail,release,cas_get,cas_put"

echo "== runner keypair =="
KG="$(deploy/secrets/runner-tool keygen 2>/dev/null)"
PUBHEX="$(printf '%s\n' "$KG" | sed -n 's/^pubkey_hex=//p')"
SEED="$(printf '%s\n' "$KG" | sed -n 's/^seed_b64=//p')"
# Fail closed: don't enroll/write a credential from an empty keygen (its stderr is swallowed).
[ -n "$PUBHEX" ] && [ -n "$SEED" ] || { echo "ERROR: runner keygen produced no keypair" >&2; exit 1; }

echo "== enroll runner ($LANES) =="
BISCUIT="$("${SIGNER[@]}" enroll --pubkey "$PUBHEX" --rights "$RIGHTS" --lanes "$LANES")"

cat > deploy/cred/cred.json <<EOF
{"biscuit":"$BISCUIT","pubkey_hex":"$PUBHEX","seed_b64":"$SEED"}
EOF
echo "== wrote deploy/cred/cred.json (runner id ${PUBHEX:0:16}...) =="
echo
echo "Next: docker compose -f compose.dev.yml up --build"
