# Deploying the dispatch plane

`compose.dev.yml` brings the whole plane up on one host for integration + E2E.
Production distributes the runner/compute pairs across the tailnet; the container
graph is identical — only the network between the runner and the PEP changes from
a compose network to the tailnet.

## Trust boundaries (as network topology)

| Network | Members | Exposed? |
|---|---|---|
| `backplane` (internal) | pep ⇄ dispatcher ⇄ cas — "loopback" | no |
| `edge` | the pep's runner + cas surfaces | yes (the only doors) |
| `worker` (internal) | a runner ⇄ its compute container | no |
| `egress` | smokescreen ⇄ internet | no (smokescreen only) |

The compute container is jailed on `worker` (internal) with no credentials and no
route out. An **ingest**-lane image (feed/download) additionally sets
`HTTP(S)_PROXY=smokescreen:4750` and is on `worker` only — so its single outbound
neighbor is the EgressGuard, which enforces the host allowlist.

## Bring-up

```sh
./deploy/bootstrap.sh embed        # issuer key + .env + a runner credential
docker compose -f compose.dev.yml up --build
```

`bootstrap.sh` mints the issuer key (or reuses an existing `deploy/secrets/secrets.json`),
writes the PEP's root public key to `.env`, generates a runner Ed25519 keypair,
enrolls it (out of band — pairing is the root of trust), and writes
`deploy/cred/cred.json`. Re-running preserves existing pairings.

## Enrolling more runners / apps

`keygen --out` writes the keypair to the credential file at 0600 and prints ONLY the
public key — the private seed never touches stdout. Enroll that pubkey, then `seal`
folds the returned Biscuit into the same file (the signer only ever sees the pubkey):

```sh
pub=$(deploy/secrets/runner-tool keygen --out deploy/cred/cred.json)
auth/target/release/signer -secrets deploy/secrets/secrets.json \
    enroll --pubkey "$pub" --rights hello,lease,heartbeat,complete,fail,release,cas_get,cas_put --lanes transcribe \
  | deploy/secrets/runner-tool seal --cred deploy/cred/cred.json --biscuit-file -
```

Apps that only use the CAS need `--rights cas_get,cas_put` and no lanes.

## Notes

- The CAS is **bazel-remote**; the PEP rewrites its `/blobs/sha256/<hex>` surface
  to bazel-remote's `/cas/<hex>` (`PEP_CAS_STYLE=bazel`).
- `deploy/secrets/`, `deploy/cred/`, and `.env` hold secrets and are gitignored.
- Cost gate defaults to `$0` (fail-closed): no priced/cloud job runs until the cap
  is raised via `dispatchctl` / config.
