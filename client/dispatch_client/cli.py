"""Operator commands use the application's existing private socket client."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .client import DispatchClient, DispatchError
from .frame import FrameError

OPERATIONS = {
    "jobs": ((), ("state", "lane", "prefix", "page")),
    "job": (("job_id",), ()),
    "trace": (("job_id",), ()),
    "wait": (("job_id",), ()),
    "lookup": (("submission_key",), ()),
    "fleet": ((), ()),
    "drain": (("runner_id",), ()),
    "resume": (("runner_id",), ()),
    "stats": ((), ("window",)),
    "budget": ((), ()),
    "cancel": (("job_id",), ("reason",)),
    "approve": (("job_id",), ("author", "reason")),
    "reject": (("job_id",), ("author", "reason")),
    "ack": (("job_id", "disposition"), ("reason",)),
    "sweep": ((), ()),
    "enqueue": ((), ("key", "lane", "inv", "cost", "submission")),
}
FIELDS = {
    "prefix": "job_key_prefix",
    "window": "window_s",
    "key": "job_key",
    "inv": "invocation_address",
    "cost": "cost_estimate_usd",
    "submission": "submission_key",
}
RUNS = ("run", "follow")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dispatchctl", allow_abbrev=False)
    parser.add_argument(
        "-addr",
        "--addr",
        default=os.environ.get("DISPATCH_ADDR"),
        required=not os.environ.get("DISPATCH_ADDR"),
        help="private app socket or host:port (default $DISPATCH_ADDR)",
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    for name, (positions, flags) in OPERATIONS.items():
        command = commands.add_parser(name, allow_abbrev=False)
        for position in positions:
            command.add_argument(position)
        for flag in flags:
            command.add_argument(
                "--" + flag,
                dest=FIELDS.get(flag, flag),
                type=int if flag in ("page", "window") else str,
                default=argparse.SUPPRESS,
                required=flag == "author" or name == "enqueue" and flag in ("key", "lane", "inv"),
            )
    run = commands.add_parser(
        "run",
        allow_abbrev=False,
        help="upload inputs, run ARGV on a worker, stream its log and fetch its outputs",
    )
    run.add_argument("--lane", required=True)
    run.add_argument("--key", dest="job_key", help="job key (default: one per lane and invocation)")
    run.add_argument("--input", action="append", default=[], metavar="NAME=PATH")
    run.add_argument("--output", action="append", default=[], metavar="NAME")
    run.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    run.add_argument("--gpu-mb", type=int, help="GPU memory the job uses at most, in MiB")
    run.add_argument("--gpu-mode", choices=("shared", "mps", "exclusive"), default="shared")
    follow = commands.add_parser(
        "follow", allow_abbrev=False, help="stream a queued job's log and fetch its outputs"
    )
    follow.add_argument("job_id")
    for command in (run, follow):
        command.add_argument(
            "--cas", default=os.environ.get("DISPATCH_CAS_URL"), help="default $DISPATCH_CAS_URL"
        )
        command.add_argument(
            "--credential",
            default=os.environ.get("DISPATCH_CREDENTIAL"),
            help="app CAS credential file (default $DISPATCH_CREDENTIAL)",
        )
        command.add_argument("--dest", help="folder for the outputs (default dispatch-out/JOB_ID)")
        command.add_argument(
            "--no-ack", action="store_true", help="leave the job in the completion inbox"
        )
    run.add_argument("argv", nargs=argparse.REMAINDER, help="-- COMMAND ARG...")
    return parser


def request(argv: list[str] | None = None) -> tuple[str, str, dict[str, Any]]:
    return _request(vars(_parser().parse_args(argv)))


def _request(body: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    address, operation = body.pop("addr"), body.pop("operation")
    if operation == "jobs":
        body["filter"] = {
            key: body.pop(key) for key in ("state", "lane", "job_key_prefix") if key in body
        }
    if operation == "enqueue":
        body = {"jobs": [body]}
    return address, "job" if operation == "trace" else operation, body


def _pairs(values: list[str], what: str) -> dict[str, str]:
    pairs = {}
    for value in values:
        name, sep, given = value.partition("=")
        if not sep or not name or name in pairs:
            raise ValueError(f"{what} {value!r}: expected one NAME=VALUE per name")
        pairs[name] = given
    return pairs


def _run(args: dict[str, Any]) -> int:
    from .cas import CasClient, CasError, Credential
    from .run import follow, run_step

    queued: list[str] = []
    try:
        if not args["cas"] or not args["credential"]:
            raise ValueError("--cas and --credential (or $DISPATCH_CAS_URL, $DISPATCH_CREDENTIAL)")
        cas = CasClient(args["cas"], Credential.load(args["credential"]))
        with DispatchClient(args["addr"], retry_requests=False) as client:
            if args["operation"] == "follow":
                queued.append(args["job_id"])
                result = follow(client, cas, args["job_id"], args["dest"], ack=not args["no_ack"])
            else:
                argv = args["argv"][1:] if args["argv"][:1] == ["--"] else args["argv"]

                def announce(job_id: str) -> None:
                    queued.append(job_id)
                    print(f"dispatchctl: queued {job_id} on {args['lane']}", file=sys.stderr)

                result = run_step(
                    client,
                    cas,
                    lane=args["lane"],
                    argv=argv,
                    inputs=_pairs(args["input"], "--input"),
                    outputs=args["output"],
                    dest=args["dest"],
                    params=_pairs(args["param"], "--param"),
                    job_key=args["job_key"],
                    gpu=(
                        None
                        if args["gpu_mb"] is None
                        else {"memory_mb": args["gpu_mb"], "mode": args["gpu_mode"]}
                    ),
                    ack=not args["no_ack"],
                    on_queued=announce,
                )
    except KeyboardInterrupt:
        if queued:
            print(
                f"dispatchctl: stopped watching; {queued[0]} goes on. "
                f"`dispatchctl follow {queued[0]}` picks it up, `dispatchctl cancel {queued[0]}` "
                "stops it.",
                file=sys.stderr,
            )
        return 130
    except (DispatchError, FrameError, CasError, OSError, ValueError) as error:
        print("dispatchctl: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result.summary(), indent=2))
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = vars(_parser().parse_args(argv))
    if args["operation"] in RUNS:
        return _run(args)
    address, operation, body = _request(args)
    try:
        with DispatchClient(address, retry_requests=False) as client:
            result = client._request(operation, body)["body"]
    except (DispatchError, FrameError, OSError, ValueError) as error:
        print("dispatchctl: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
