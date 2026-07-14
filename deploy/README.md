# Local integration deployment

`compose.dev.yml` is a standalone integration stack for the plane. It is not the
easy-podcast production deployment. easy-podcast owns the production topology and runs it
through
[`deploy/easypod`](https://github.com/falahat/easy-podcast/blob/main/deploy/easypod).

## Topology

| Network | Members | Host exposure |
|---|---|---|
| `backplane` | PEP, dispatcher, CAS | none |
| `edge` | PEP and runner | PEP ports `7443` and `8443` |
| `invoke` | runner and echo compute | none |

The echo compute has no credential and no internet route. Application deployments add
their own compute and ingest egress guards on separate internal networks.

## Start

```sh
./deploy/bootstrap.sh embed
docker compose -f compose.dev.yml up --build
```

Bootstrap preserves an existing issuer key and pairing registry, writes the issuer public
key to `.env`, and creates a mode-`0600` runner credential under `deploy/cred/`. The private
holder seed stays in that credential file.

Stop and remove the local containers with:

```sh
docker compose -f compose.dev.yml down
```

The CAS rewrites Bazel Remote Cache paths behind the PEP. The default priced-work cap is
`$0.00`, so this stack cannot admit cloud-priced work.
