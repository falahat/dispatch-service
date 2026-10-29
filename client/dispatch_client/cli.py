"""Operator commands use the application's existing private socket client."""

from __future__ import annotations

import argparse
import json
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


def request(argv: list[str] | None = None) -> tuple[str, str, dict[str, Any]]:
    parser = argparse.ArgumentParser(prog="dispatchctl", allow_abbrev=False)
    parser.add_argument("-addr", "--addr", required=True, help="private app socket or host:port")
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
    body = vars(parser.parse_args(argv))
    address, operation = body.pop("addr"), body.pop("operation")
    if operation == "jobs":
        body["filter"] = {
            key: body.pop(key) for key in ("state", "lane", "job_key_prefix") if key in body
        }
    if operation == "enqueue":
        body = {"jobs": [body]}
    return address, "job" if operation == "trace" else operation, body


def main(argv: list[str] | None = None) -> int:
    address, operation, body = request(argv)
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
