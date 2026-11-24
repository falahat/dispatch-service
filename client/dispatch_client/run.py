"""One call runs a command on a worker: upload its inputs, queue it, stream its log, fetch its outputs.

``run_step`` is the Python form and ``dispatchctl run`` the command-line one. The invocation they build
carries the command in ``params.argv`` and the output names in ``params.outputs``; the worker's
installed command (contracts/COMMAND.md) runs that argv. ``follow`` picks up a job already queued.
A local input (a ``Place``) is read where it lies on its node and pins the job there; a kept output
(``keep``, ``params.keep``) is written where it is to stay, under a root of the job's node, and like
any local output it is reported, not fetched (contracts/ARTIFACTS.md).
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from .cas import CasClient
from .client import DispatchClient

_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class Place:
    """A file or folder where it lies on ``node``, at ``path`` under its runner's root ``root``."""

    node: str
    root: str
    path: str

    @classmethod
    def parse(cls, text: str) -> Place:
        """Read ``NODE:ROOT/PATH``."""
        node, colon, rest = text.partition(":")
        root, slash, path = rest.partition("/")
        if not colon or not slash:
            raise ValueError(f"local place {text!r}: expected NODE:ROOT/PATH")
        return cls(node, root, path).checked()

    def checked(self) -> Place:
        segments = self.path.split("/")
        if (
            not _NODE_RE.match(self.node)
            or not _NAME_RE.match(self.root)
            or any(part in ("", ".", "..") for part in segments)
            or any(char == "\\" or ord(char) < 0x20 for char in self.path)
        ):
            raise ValueError(f"local place {self}: invalid node, root or path")
        return self

    def artifact(self) -> dict[str, str]:
        return {"kind": "local", "node": self.node, "root": self.root, "path": self.path}

    def __str__(self) -> str:
        return f"{self.node}:{self.root}/{self.path}"


@dataclass
class RunResult:
    """What a run produced.

    ``state`` is the job's state when the run ended: SUCCEEDED once its outputs were saved and
    acknowledged, PERSISTING when saved without acknowledging. ``local`` holds the outputs kept
    where they lie on the worker's node. ``seconds`` holds ``upload``,
    ``queued`` (submit to start), ``run`` (start to result; both on the dispatcher's clock),
    ``fetch`` and ``total``. ``bytes`` holds the CAS traffic of this run: ``uploaded``,
    ``already_stored`` (inputs the store held, not sent) and ``downloaded`` (outputs and log).
    """

    job_id: str
    state: str
    outputs: dict[str, Path]
    local: dict[str, Place]
    metrics: dict[str, Any]
    seconds: dict[str, Optional[float]]
    bytes: dict[str, int]
    job: dict[str, Any]

    @property
    def ok(self) -> bool:
        """The job finished, its outputs were saved, and its ``exit`` metric, if any, is zero."""
        return self.state in ("SUCCEEDED", "PERSISTING") and self.metrics.get("exit", 0) == 0

    def summary(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state,
            "reason": self.job.get("reason") or None,
            "outputs": {name: str(path) for name, path in self.outputs.items()},
            "local": {name: str(place) for name, place in self.local.items()},
            "metrics": self.metrics,
            "seconds": self.seconds,
            "bytes": self.bytes,
        }


def _check_params(value: Any, where: str) -> None:
    """The artifacts contract allows integers but no other numbers in params."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{where}: keys must be strings")
            _check_params(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_params(item, f"{where}[{index}]")
    elif isinstance(value, float):
        raise ValueError(f"{where}: numbers must be integers (write decimals as strings)")
    elif not (value is None or isinstance(value, (str, int))):
        raise ValueError(f"{where}: {type(value).__name__} is not JSON")


def upload_inputs(cas: CasClient, inputs: Mapping[str, str | Path]) -> dict[str, dict[str, str]]:
    """Store each input: a file as a blob, a folder as a manifest of its files."""
    stored = {}
    for name, given in sorted(inputs.items()):
        if not _NAME_RE.match(name):
            raise ValueError(f"input name {name!r} must match [a-z0-9_]{{1,64}}")
        path = Path(given)
        if path.is_dir():
            stored[name] = {"address": cas.put_folder(path), "kind": "manifest"}
        elif path.is_file():
            stored[name] = {"address": cas.put_file(path), "kind": "blob"}
        else:
            raise ValueError(f"input {name}: {path} is not a file or a folder")
    return stored


def submit(
    client: DispatchClient,
    cas: CasClient,
    *,
    lane: str,
    argv: Sequence[str],
    inputs: Optional[Mapping[str, str | Path]] = None,
    outputs: Sequence[str] = (),
    params: Optional[Mapping[str, Any]] = None,
    job_key: Optional[str] = None,
    gpu: Optional[Mapping[str, Any]] = None,
    local: Optional[Mapping[str, Place]] = None,
    node: Optional[str] = None,
    keep: Optional[Mapping[str, str]] = None,
    policy: Optional[Mapping[str, Any]] = None,
    cost_estimate_usd: Optional[str] = None,
    op: str = "run",
    op_version: int = 1,
) -> str:
    """Upload ``inputs``, store the invocation and queue it on ``lane``; returns the job id.

    ``job_key`` defaults to one derived from the lane and the invocation, so submitting the same
    run while it is queued or running joins that job instead of starting another. ``gpu`` is the
    job's GPU need, e.g. ``{"memory_mb": 8192, "mode": "shared"}``. ``local`` inputs are read where
    they lie and pin the job to their node; ``node`` pins a job without them. ``keep`` names
    outputs the command writes where they are to stay, ``{name: "ROOT/PATH"}`` under the roots
    of the job's node. ``policy`` holds the rest of the job's policy (``max_attempts``,
    ``backoff_class``, ...; WIRE.md), and ``cost_estimate_usd`` ("1.25") prices the job: it waits
    for approval against the plane's budget.
    """
    if not argv or not all(isinstance(arg, str) for arg in argv):
        raise ValueError("argv must be a non-empty list of strings")
    for name in outputs:
        if not _NAME_RE.match(name):
            raise ValueError(f"output name {name!r} must match [a-z0-9_]{{1,64}}")
    extra = dict(params or {})
    if {"argv", "outputs", "keep"} & extra.keys():
        raise ValueError("params may not set argv, outputs or keep")
    _check_params(extra, "params")
    places = {name: place.checked() for name, place in (local or {}).items()}
    for name in places:
        if not _NAME_RE.match(name) or name in (inputs or {}):
            raise ValueError(f"local input name {name!r} must match [a-z0-9_]{{1,64}} once")
    nodes = {place.node for place in places.values()} | ({node} if node else set())
    if len(nodes) > 1:
        raise ValueError(f"a job runs on one node, not {sorted(nodes)}")
    if keep and not nodes:
        raise ValueError("a kept output needs the job's node: a local input or node")
    kept = {name: Place.parse(f"{next(iter(nodes))}:{text}") for name, text in (keep or {}).items()}
    for name in kept:
        if not _NAME_RE.match(name) or name in outputs:
            raise ValueError(f"kept output name {name!r} must match [a-z0-9_]{{1,64}} once")
    invocation = {
        "kind": "invocation/v0",
        "op": op,
        "op_version": op_version,
        "params": {
            **extra,
            "argv": list(argv),
            "outputs": list(outputs),
            **(
                {"keep": {n: {"root": p.root, "path": p.path} for n, p in kept.items()}}
                if kept
                else {}
            ),
        },
        "inputs": {
            **upload_inputs(cas, inputs or {}),
            **{name: place.artifact() for name, place in places.items()},
        },
    }
    address = cas.put_json(invocation)
    job: dict[str, Any] = {
        "job_key": job_key or f"run-{lane}-{address[len('sha256:'):][:32]}",
        "lane": lane,
        "invocation_address": address,
    }
    rules = dict(policy or {})
    if {"gpu", "node"} & rules.keys():
        raise ValueError("policy may not set gpu or node: pass gpu, node or a local input")
    if gpu is not None:
        rules["gpu"] = dict(gpu)
    if nodes:
        rules["node"] = nodes.pop()
    if rules:
        job["policy"] = rules
    if cost_estimate_usd is not None:
        job["cost_estimate_usd"] = cost_estimate_usd
    return str(client.enqueue([job])[0]["job_id"])


def fetch_outputs(cas: CasClient, result: Mapping[str, Any], dest: Path) -> dict[str, Path]:
    """Save each output of an action result under ``dest/<name>``: a blob as a file, a manifest
    as a folder. Nothing already at ``dest/<name>`` is replaced; local outputs stay where they
    lie."""
    outputs = {
        name: output
        for name, output in (result.get("outputs") or {}).items()
        if output.get("kind") != "local"
    }
    if not outputs:
        return {}
    for name in outputs:
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ValueError(f"output name {name!r} must match [a-z0-9_]{{1,64}}")
        if (dest / name).exists() or (dest / name).is_symlink():
            raise FileExistsError(f"{dest / name} already exists")
    dest.mkdir(parents=True, exist_ok=True)
    saved = {}
    for name, output in sorted(outputs.items()):
        target = dest / name
        if output.get("kind") == "manifest":
            cas.get_folder(output["address"], target)
        elif cas.get_to_file(output["address"], target) != output.get("size"):
            raise ValueError(f"output {name}: size differs from the result")
        saved[name] = target
    return saved


def _stderr(data: bytes) -> None:
    sys.stderr.buffer.write(data)
    sys.stderr.buffer.flush()


def _timeline_seconds(job: Mapping[str, Any]) -> tuple[Optional[float], Optional[float]]:
    """Submit to first start, and last start to its result, from the job's timeline."""
    line = job.get("timeline") or []
    queued = [entry["ts"] for entry in line if entry["outcome"] == "enqueue"]
    started = [entry["ts"] for entry in line if entry["outcome"] == "claimed"]
    ended = [entry["ts"] for entry in line if entry["outcome"] in ("complete", "fail")]
    wait = (started[0] - queued[0]) / 1000 if queued and started else None
    run = (
        (ended[-1] - started[-1]) / 1000 if started and ended and ended[-1] >= started[-1] else None
    )
    return wait, run


def follow(
    client: DispatchClient,
    cas: CasClient,
    job_id: str,
    dest: Optional[str | Path] = None,
    *,
    log: Optional[Callable[[bytes], None]] = None,
    ack: bool = True,
) -> RunResult:
    """Stream a job's log to ``log`` (stderr by default) until it ends, save its outputs under
    ``dest`` (default ``dispatch-out/<job id>``) and acknowledge it. A job that failed or was
    cancelled returns with no outputs; one left unacknowledged stays in the completion inbox."""
    began = time.monotonic()
    before = dict(cas.transferred)
    write = log or _stderr
    after = 0
    while True:
        page = client.logs(job_id, after=after, wait=True)
        for entry in page["entries"]:
            write(cas.get(entry["address"]))
        after = page["next_offset"]
        if page["done"]:
            break
    job = client.job(job_id)
    result = job.get("action_result")
    if isinstance(result, str):
        result = json.loads(result)
    outputs: dict[str, Path] = {}
    local: dict[str, Place] = {}
    metrics: dict[str, Any] = {}
    fetched = None
    if job["state"] in ("PERSISTING", "SUCCEEDED") and isinstance(result, dict):
        start = time.monotonic()
        outputs = fetch_outputs(cas, result, Path(dest) if dest else Path("dispatch-out", job_id))
        fetched = round(time.monotonic() - start, 3)
        local = {
            name: Place(output["node"], output["root"], output["path"])
            for name, output in (result.get("outputs") or {}).items()
            if output.get("kind") == "local"
        }
        metrics = dict(result.get("metrics") or {})
        if ack and job["state"] == "PERSISTING":
            client.ack(job_id, "persisted")
            job = client.job(job_id)
    wait, run = _timeline_seconds(job)
    return RunResult(
        job_id=job_id,
        state=job["state"],
        outputs=outputs,
        local=local,
        metrics=metrics,
        seconds={
            "queued": wait,
            "run": run,
            "fetch": fetched,
            "total": round(time.monotonic() - began, 3),
        },
        bytes={key: cas.transferred[key] - before[key] for key in before},
        job=job,
    )


def run_step(
    client: DispatchClient,
    cas: CasClient,
    *,
    lane: str,
    argv: Sequence[str],
    inputs: Optional[Mapping[str, str | Path]] = None,
    outputs: Sequence[str] = (),
    dest: Optional[str | Path] = None,
    params: Optional[Mapping[str, Any]] = None,
    job_key: Optional[str] = None,
    gpu: Optional[Mapping[str, Any]] = None,
    local: Optional[Mapping[str, Place]] = None,
    node: Optional[str] = None,
    keep: Optional[Mapping[str, str]] = None,
    policy: Optional[Mapping[str, Any]] = None,
    cost_estimate_usd: Optional[str] = None,
    op: str = "run",
    op_version: int = 1,
    log: Optional[Callable[[bytes], None]] = None,
    ack: bool = True,
    on_queued: Optional[Callable[[str], None]] = None,
) -> RunResult:
    """``submit`` then ``follow``: one call from local files to local outputs.

    ``on_queued`` receives the job id as soon as the job is queued, so a caller that stops
    watching can pick the job up again with ``follow``.
    """
    began = time.monotonic()
    before = dict(cas.transferred)
    job_id = submit(
        client,
        cas,
        lane=lane,
        argv=argv,
        inputs=inputs,
        outputs=outputs,
        params=params,
        job_key=job_key,
        gpu=gpu,
        local=local,
        node=node,
        keep=keep,
        policy=policy,
        cost_estimate_usd=cost_estimate_usd,
        op=op,
        op_version=op_version,
    )
    uploaded = round(time.monotonic() - began, 3)
    if on_queued is not None:
        on_queued(job_id)
    result = follow(client, cas, job_id, dest, log=log, ack=ack)
    result.seconds = {"upload": uploaded, **result.seconds}
    result.seconds["total"] = round(time.monotonic() - began, 3)
    result.bytes = {key: cas.transferred[key] - before[key] for key in before}
    return result
