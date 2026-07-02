#!/usr/bin/env python3
"""echo compute container — a reference implementation of the INVOKE contract v0.

Standard library only. Serves HTTP/1.1 on INVOKE_ADDR (host:port) with exactly two
endpoints:

    GET  /healthz  -> readiness probe
    POST /invoke   -> run one echo computation

The echo op copies each declared input into the outputs directory (or, when there are
no inputs, writes the invocation params to outputs/echo.json). It touches nothing outside
workdir/inputs/** (read) and workdir/<outputs_dir>/** (write); it makes no network calls
and holds no credentials.
"""

import json
import os
import re
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OP = "echo"
OP_VERSION = 1

# Optional artificial delay (milliseconds) applied inside /invoke so a self-test can force
# two requests to overlap. The normal path is never slowed (unset/0 => no delay).
ECHO_SLEEP_MS = int(os.environ.get("ECHO_SLEEP_MS", "0") or "0")

# A relative path under workdir: no leading slash, no ".." segment, no backslash, no NUL /
# control chars. Mirrors the artifacts schema's relative_path guard; re-checked here because
# the runner's layout is untrusted input to this container.
_REL_PATH = re.compile(r"^(?!/)(?!.*(^|/)\.\.(/|$))[^\\\x00-\x1f]+$")


class BadInput(Exception):
    """A malformed request body, missing input file, or otherwise unusable request."""


class Deadline(Exception):
    """The invocation's deadline had already passed."""


class InvokeLock:
    """Non-blocking single-flight guard. try_acquire() returns False instead of blocking."""

    def __init__(self):
        self._lock = threading.Lock()

    def try_acquire(self):
        return self._lock.acquire(blocking=False)

    def release(self):
        self._lock.release()


_invoke_lock = InvokeLock()


def _safe_join(workdir, rel):
    """Join a runner-supplied relative path onto workdir, refusing traversal/escape.

    Returns an absolute path guaranteed to live inside workdir. Raises BadInput otherwise.
    """
    if not isinstance(rel, str) or not _REL_PATH.match(rel):
        raise BadInput(f"unsafe relative path: {rel!r}")
    base = os.path.realpath(workdir)
    full = os.path.realpath(os.path.join(base, rel))
    if full != base and not full.startswith(base + os.sep):
        raise BadInput(f"path escapes workdir: {rel!r}")
    return full


def run_invoke(req):
    """Execute one echo computation. Returns the /invoke success body (a dict)."""
    if not isinstance(req, dict):
        raise BadInput("request body must be a JSON object")

    workdir = req.get("workdir")
    if not isinstance(workdir, str) or not workdir:
        raise BadInput("missing or invalid 'workdir'")
    if not os.path.isdir(workdir):
        raise BadInput(f"workdir does not exist: {workdir!r}")

    outputs_dir = req.get("outputs_dir")
    if not isinstance(outputs_dir, str) or not outputs_dir:
        raise BadInput("missing or invalid 'outputs_dir'")

    invocation = req.get("invocation")
    if not isinstance(invocation, dict):
        raise BadInput("missing or invalid 'invocation'")

    inputs = req.get("inputs")
    if inputs is None:
        inputs = {}
    if not isinstance(inputs, dict):
        raise BadInput("'inputs' must be an object")

    # Honor the deadline: if it has already passed, do no work.
    deadline_ts = req.get("deadline_ts")
    if deadline_ts is not None:
        if not isinstance(deadline_ts, int) or isinstance(deadline_ts, bool):
            raise BadInput("'deadline_ts' must be an integer (ms epoch)")
        if _now_ms() >= deadline_ts:
            raise Deadline("deadline already passed")

    # Resolve and pre-validate the outputs directory (must stay inside workdir).
    outputs_abs = _safe_join(workdir, outputs_dir)
    os.makedirs(outputs_abs, exist_ok=True)

    if ECHO_SLEEP_MS > 0:
        time.sleep(ECHO_SLEEP_MS / 1000.0)

    outputs = {}
    total_bytes = 0

    if inputs:
        for name, rel in inputs.items():
            if not _is_valid_name(name):
                raise BadInput(f"invalid input name: {name!r}")
            if not isinstance(rel, str):
                raise BadInput(f"input path for {name!r} must be a string")
            src = _safe_join(workdir, rel)
            if not os.path.isfile(src):
                raise BadInput(f"input file missing: {rel!r}")
            dst_rel = f"{outputs_dir}/{name}"
            dst = _safe_join(workdir, dst_rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
            total_bytes += os.path.getsize(dst)
            outputs[name] = dst_rel
    else:
        # No inputs: echo the invocation's params object as a single JSON output.
        params = invocation.get("params", {})
        if not isinstance(params, dict):
            raise BadInput("'invocation.params' must be an object")
        dst_rel = f"{outputs_dir}/echo.json"
        dst = _safe_join(workdir, dst_rel)
        data = json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with open(dst, "wb") as fh:
            fh.write(data)
        total_bytes += len(data)
        outputs["echo"] = dst_rel

    # Metrics MUST be integers.
    return {
        "outputs": outputs,
        "metrics": {"bytes": int(total_bytes), "outputs": int(len(outputs))},
    }


def _is_valid_name(name):
    return isinstance(name, str) and re.match(r"^[a-z0-9_]{1,64}$", name) is not None


def _now_ms():
    return int(time.time() * 1000)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._write_json(200, {"ready": True, "op": OP, "op_version": OP_VERSION})
        else:
            self._write_json(404, {"error_class": "bad_input", "message": "not found"})

    def do_POST(self):
        if self.path != "/invoke":
            self._write_json(404, {"error_class": "bad_input", "message": "not found"})
            return

        # Single-flight: refuse a second concurrent invoke without blocking.
        if not _invoke_lock.try_acquire():
            self._write_json(409, {"error_class": "fatal", "message": "invoke already in flight"})
            return
        try:
            try:
                req = self._read_json_body()
            except BadInput as exc:
                self._write_json(500, {"error_class": "bad_input", "message": str(exc)})
                return

            try:
                result = run_invoke(req)
            except BadInput as exc:
                self._write_json(500, {"error_class": "bad_input", "message": str(exc)})
                return
            except Deadline as exc:
                self._write_json(500, {"error_class": "timeout", "message": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001 — internal failure is 'unknown'
                self._write_json(500, {"error_class": "unknown", "message": repr(exc)})
                return

            self._write_json(200, result)
        finally:
            _invoke_lock.release()

    def _read_json_body(self):
        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None:
            raise BadInput("missing Content-Length")
        try:
            length = int(length_hdr)
        except ValueError:
            raise BadInput("invalid Content-Length")
        if length < 0:
            raise BadInput("negative Content-Length")
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise BadInput(f"malformed JSON body: {exc}")

    def log_message(self, *args):
        # Keep stdout quiet; the runner does not read our access log.
        pass


def _parse_addr(addr):
    """Split a host:port INVOKE_ADDR. UDS paths are out of scope for this reference image."""
    host, sep, port = addr.rpartition(":")
    if not sep or not host:
        raise SystemExit(f"INVOKE_ADDR must be host:port, got: {addr!r}")
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit(f"INVOKE_ADDR has a non-integer port: {addr!r}")


def main():
    addr = os.environ.get("INVOKE_ADDR")
    if not addr:
        # An unrecoverable startup misconfiguration: exit non-zero.
        print("INVOKE_ADDR is not set", file=sys.stderr)
        sys.exit(1)

    host, port = _parse_addr(addr)
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"failed to bind {addr}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"echo compute ready on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
