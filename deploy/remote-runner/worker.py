"""Apply one worker profile; dispatch owns admission, tailworker owns transport."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


def checked_json(path):
    for parent in (path.parent, path.parent.parent):
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
        ):
            raise ValueError("worker state directory must be owned and protected")
    with os.fdopen(
        os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    ) as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 65536
        ):
            raise ValueError("worker state must be an owned private regular file")
        return json.loads(source.read(65537))


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def image_id(value):
    digest = value.strip().removeprefix("sha256:")
    if not re.fullmatch("[0-9a-f]{64}", digest):
        raise ValueError("invalid installed image identity")
    return "sha256:" + digest


def worker_state(name, action):
    """Runs on the worker. Only public configuration/identities leave this function."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
        raise ValueError("invalid worker profile name")
    base = Path.home() / ".config/plane-runners" / name
    if not (base / "profile.json").exists():
        return None
    profile = checked_json(base / "profile.json")
    native = profile["MODE"] == "command"
    runners = []
    for index in range(1, int(profile["COUNT"]) + 1):
        credential = checked_json(
            base / "cred" / (f"{index}.json" if native else "runner.json")
        )
        identity = credential.get("pubkey_hex", "")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", identity)
            or not credential.get("biscuit")
            or not credential.get("seed_b64")
        ):
            raise ValueError("incomplete worker enrollment; inspect before continuing")
        unit = f"{name}-runner@{index}.service" if native else f"{name}-runner.service"
        while True:
            fields = dict(
                line.split("=", 1)
                for line in command(
                    [
                        "systemctl",
                        "--user",
                        "show",
                        unit,
                        "--property=ActiveState,Result",
                    ],
                    capture_output=True,
                ).stdout.splitlines()
            )
            if action != "settle" or fields["ActiveState"] not in (
                "active",
                "activating",
                "deactivating",
            ):
                break
            time.sleep(0.25)
        if action == "settle" and (
            fields["ActiveState"] != "inactive" or fields["Result"] != "success"
        ):
            raise ValueError(
                "runner did not drain cleanly; inspect it before replacing"
            )
        runners.append(
            {"runner_id": identity, "active": fields["ActiveState"] == "active"}
        )
    if action == "settle" and not native:
        command(["systemctl", "--user", "stop", f"{name}-compute.service"])
        if "SMOKESCREEN_IMAGE" in profile:
            command(["systemctl", "--user", "stop", f"{name}-smokescreen.service"])
    images = {}
    if action == "inspect" and not native:
        for role in ("runner", "compute", "smokescreen"):
            if role.upper() + "_IMAGE" not in profile:
                continue
            result = subprocess.run(
                [
                    "podman",
                    "container",
                    "inspect",
                    "--format",
                    "{{.Image}} {{.State.Running}}",
                    f"{name}-{role}",
                ],
                capture_output=True,
                text=True,
            )
            value = result.stdout.split()
            images[role + "_image"] = (
                image_id(value[0])
                if result.returncode == 0 and len(value) == 2 and value[1] == "true"
                else ""
            )
    return {
        "profile": profile,
        "runners": runners,
        **images,
        "active": all(runner["active"] for runner in runners) and all(images.values()),
    }


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("operation", choices=("apply", "status"))
    parser.add_argument("--env", type=Path)
    parser.add_argument("--name")
    parser.add_argument("--machine", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--signer")
    parser.add_argument("--note")
    parser.add_argument("--runner")
    parser.add_argument("--secret", nargs=2, action="append", default=[])
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from worker_profile import render

    def remote(*argv, **kwargs):
        return command(
            [
                "bash",
                "-c",
                'source "$1/common.sh"; shift; remote "$@"',
                "_",
                str(here),
                endpoint,
                *argv,
            ],
            **kwargs,
        )

    # Resolve once: common.remote takes the endpoint, not its logical discovery name.
    endpoint = json.loads(
        command(["tailworker", "resolve", args.machine], capture_output=True).stdout
    )["host"]

    def state(action):
        return json.loads(
            remote(
                "python3",
                "-",
                args.name,
                action,
                input=Path(__file__).read_text(),
                capture_output=True,
            ).stdout
        )

    def control(verb, *positions):
        return json.loads(
            command(
                ["bash", "-c", args.client + ' "$@"', "_", verb, *positions],
                capture_output=True,
            ).stdout
        )

    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory)
        desired = None
        environment = stage / "settings.env"
        if args.env:
            environment.write_bytes(args.env.read_bytes())
            desired = render(here, environment, stage, bool(args.runner))
            if args.name and args.name != desired["NAME"]:
                parser.error("--name and --env disagree")
            args.name = desired["NAME"]
        if (
            not args.name
            or args.operation == "apply"
            and (desired is None or not args.signer or not args.note)
        ):
            parser.error(
                "apply needs --env, --signer and --note; status needs --env or --name"
            )
        current = state("inspect")
        if args.operation == "apply":
            if current:
                invariant = (
                    "MODE",
                    "NAME",
                    "LANES",
                    "COUNT",
                    "PLANE_ADDR",
                    "DISPATCHER_ADDR",
                    "CAS_URL",
                )
                if any(
                    current["profile"].get(key) != desired.get(key) for key in invariant
                ):
                    raise ValueError(
                        "changing worker identity, scope or coordinator requires explicit enrollment"
                    )
                for runner in current["runners"]:
                    control("drain", runner["runner_id"])
                state("settle")
            install = [
                "bash",
                str(here / "install.sh"),
                "--env",
                str(environment),
                "--machine",
                args.machine,
            ]
            if args.runner:
                install += ["--runner", args.runner]
            for secret in args.secret:
                install += ["--secret", *secret]
            command(install)
            previous = control("fleet").get("runners") or []
            enroll = [
                "bash",
                str(here / "enroll.sh"),
                "--name",
                args.name,
                "--machine",
                args.machine,
            ]
            if current:
                for runner in current["runners"]:
                    control("resume", runner["runner_id"])
                enroll += ["--reuse"]
            else:
                enroll += ["--signer", args.signer, "--note", args.note]
            command(enroll)
        else:
            previous = []
        while True:
            current = state("inspect")
            fleet = {
                runner["runner_id"]: runner
                for runner in control("fleet").get("runners") or []
            }
            runners = (
                []
                if current is None
                else [
                    fleet.get(runner["runner_id"], {}) for runner in current["runners"]
                ]
            )
            ready = bool(runners) and all(
                runner.get("online")
                and not runner["draining"]
                and not runner["quarantined"]
                for runner in runners
            )
            ready = ready and current["active"]
            if current and current["profile"]["MODE"] == "http":
                ready = ready and all(
                    current[role + "_image"]
                    == current["profile"][role.upper() + "_IMAGE"]
                    for role in ("runner", "compute", "smokescreen")
                    if role.upper() + "_IMAGE" in current["profile"]
                )
            if (
                args.operation == "status"
                or ready
                and all(
                    runner["last_seen_ts"]
                    > next(
                        (
                            old["last_seen_ts"]
                            for old in previous
                            if old["runner_id"] == runner["runner_id"]
                        ),
                        0,
                    )
                    for runner in runners
                )
            ):
                break
            if current and not current["active"]:
                raise ValueError("worker failed to start; inspect its service")
            time.sleep(0.25)
        if desired and current:
            # Resolve reviewed tags on the worker; status compares immutable local IDs.
            for key in ("RUNNER_IMAGE", "COMPUTE_IMAGE", "SMOKESCREEN_IMAGE"):
                if key in desired:
                    desired[key] = image_id(
                        remote(
                            "podman",
                            "image",
                            "inspect",
                            "--format",
                            "{{.Id}}",
                            desired[key],
                            capture_output=True,
                        ).stdout
                    )
            ready = ready and all(
                current["profile"].get(key) == value for key, value in desired.items()
            )
        print(
            json.dumps(
                {"ready": bool(ready), **(current or {}), "runners": runners}, indent=2
            )
        )
        return 0 if ready else 1


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[2] in ("inspect", "settle"):
            print(json.dumps(worker_state(*sys.argv[1:])))
        else:
            sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("worker: " + str(error), file=sys.stderr)
        sys.exit(1)
