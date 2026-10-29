# Shared deployment kit

Tailworker owns approved environments, private SSH and machine discovery.
Dispatch-service owns queue/runner credentials and service installation.
Applications supply queue policy, workload configuration and the signer command.
All state lives outside Git in private owned directories.

## Coordinator

Install reviewed binaries at `ROOT/bin/runner`, this kit at `ROOT/dispatch/kit`,
and copy `plane.sh` to `ROOT/bin/plane.sh`. Supply `ROOT/dispatch/plane.json`:

```json
{"address":"100.64.0.1","runner_port":7443,"cas_port":8443,"dispatcher_image":"sha256:REVIEWED","auth_image":"sha256:REVIEWED","cas_image":"registry/IMAGE@sha256:REVIEWED"}
```

Supply the application's `ROOT/dispatch/plane.toml`. Its backend endpoints must
be `runner_listen="127.0.0.1:7700"`, `app_socket="/work/plane/app.sock"`,
`app_listen=""`, and `db_path="/work/plane/queue.db"`. All other queue settings
belong to the application. Run `bash ROOT/bin/plane.sh ROOT init`; only the PEP's
private ports are published. Images are pinned to installed IDs. The issuer
stays in `ROOT/secrets`; `info` reports public enrollment settings and `sign`
provides the shared signer adapter. Compute never receives issuer credentials.

## Workers

The same installer and enrollment lifecycle serve both executor types:

```sh
bash deploy/remote-runner/install.sh --env APP.env --machine MACHINE
bash deploy/remote-runner/enroll.sh --name APP --machine MACHINE --signer COMMAND --note NOTE
```

Add `--runner REVIEWED_BINARY` to install an owner-reviewed command executor;
HTTP compute instead declares its pinned runner/compute images. Public settings
and supported fields are documented in the [README](../README.md#add-a-worker).
No shell code or secret values belong in APP.env. Optional `--secret NAME FILE`
installs an owned mode-0600 provider secret only for HTTP compute.

Installation starts nothing and refuses active application units. Enrollment
creates a unique worker credential, signs only its public key through standard
input, and starts that application's units. Existing credentials are refused;
inspect partial setup before repeating it. Key revocation remains with the
application signer. No cloud API, network-policy change or machine creation is
part of this kit. `test-install.sh` tests both adapters without real credentials
or services; the hand-written auth/egress tests remain unchanged.
