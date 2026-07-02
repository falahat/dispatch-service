#!/usr/bin/env python3
"""Self-test for the echo compute image against the INVOKE contract v0.

Standard library only. Builds the image, runs the container against a temp workdir, and
asserts the healthz/invoke/409/timeout/bad_input behaviors. Exits non-zero on any failure
and prints PASS/FAIL lines.

Usage:  python test.py            # builds echo-compute:test and runs the suite
"""

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "echo-compute:test"
CONTAINER = "echo-compute-test"


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(port, method, path, body=None, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {}
        payload = None
        if body is not None:
            payload = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(payload))
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, raw
    finally:
        conn.close()


PASSED = 0


def check(label, cond, detail=""):
    global PASSED
    if cond:
        print(f"PASS: {label}")
        PASSED += 1
    else:
        print(f"FAIL: {label}{(' — ' + detail) if detail else ''}")
        raise AssertionError(label)


def _cleanup():
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, text=True)


def _wait_healthy(port, deadline_s=30):
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            status, raw = _http(port, "GET", "/healthz", timeout=2)
            if status == 200:
                return json.loads(raw)
        except (ConnectionRefusedError, socket.timeout, OSError, http.client.HTTPException):
            pass
        time.sleep(0.3)
    raise TimeoutError("container never became healthy")


def main():
    print("=== building image ===")
    build = _run(["docker", "build", "-t", IMAGE, HERE])
    print(build.stdout[-2000:] if build.stdout else "(build ok)")

    _cleanup()

    workdir_host = tempfile.mkdtemp(prefix="echo-work-")
    # Lay out inputs/data the way the runner would.
    os.makedirs(os.path.join(workdir_host, "inputs"), exist_ok=True)
    with open(os.path.join(workdir_host, "inputs", "data"), "wb") as fh:
        fh.write(b"hello echo\n")

    port = _free_port()
    container_workdir = "/work/job"

    print("=== running container ===")
    # Mount the host workdir at the container's workdir path; enable ECHO_SLEEP_MS so the
    # concurrency test can force two /invoke calls to overlap.
    _run([
        "docker", "run", "-d", "--name", CONTAINER,
        "-p", f"127.0.0.1:{port}:8080",
        "-e", "INVOKE_ADDR=0.0.0.0:8080",
        "-e", "ECHO_SLEEP_MS=1500",
        "-v", f"{workdir_host}:{container_workdir}",
        IMAGE,
    ])

    try:
        health = _wait_healthy(port)
        check("healthz reports ready", health.get("ready") is True, str(health))
        check("healthz op/op_version", health.get("op") == "echo" and health.get("op_version") == 1, str(health))

        # ---- valid invoke with an input ----
        req = {
            "job_id": "j_test",
            "invocation": {
                "kind": "invocation/v0", "op": "echo", "op_version": 1,
                "params": {"k": 1, "s": "v", "b": True}, "inputs": {},
            },
            "workdir": container_workdir,
            "inputs": {"data": "inputs/data"},
            "outputs_dir": "outputs",
            "deadline_ts": int(time.time() * 1000) + 60000,
        }
        status, raw = _http(port, "POST", "/invoke", req, timeout=15)
        body = json.loads(raw)
        check("invoke returns 200", status == 200, f"status={status} body={body}")
        check("invoke outputs map", body.get("outputs") == {"data": "outputs/data"}, str(body))
        metrics = body.get("metrics", {})
        check("metrics.bytes correct", metrics.get("bytes") == len(b"hello echo\n"), str(metrics))
        check("metrics.outputs correct", metrics.get("outputs") == 1, str(metrics))
        check(
            "all metrics are integers",
            all(isinstance(v, int) and not isinstance(v, bool) for v in metrics.values()),
            str(metrics),
        )
        out_file = os.path.join(workdir_host, "outputs", "data")
        check("output file exists in workdir", os.path.isfile(out_file), out_file)
        with open(out_file, "rb") as fh:
            check("output file content matches input", fh.read() == b"hello echo\n")

        # ---- concurrency: one of two overlapping invokes must get 409 ----
        results = {}

        def fire(tag):
            try:
                st, rb = _http(port, "POST", "/invoke", req, timeout=15)
                results[tag] = (st, rb)
            except Exception as exc:  # noqa: BLE001
                results[tag] = ("ERR", repr(exc).encode())

        t1 = threading.Thread(target=fire, args=("a",))
        t2 = threading.Thread(target=fire, args=("b",))
        t1.start()
        time.sleep(0.2)  # ensure 'a' grabs the lock first (ECHO_SLEEP_MS=1500 keeps it held)
        t2.start()
        t1.join()
        t2.join()
        statuses = sorted(str(results[t][0]) for t in ("a", "b"))
        check("overlapping invokes -> one 200 and one 409", statuses == ["200", "409"], str(results))

        # ---- deadline in the past -> timeout ----
        past = dict(req)
        past["deadline_ts"] = int(time.time() * 1000) - 1000
        status, raw = _http(port, "POST", "/invoke", past, timeout=15)
        body = json.loads(raw)
        check("past deadline -> 500", status == 500, f"status={status}")
        check("past deadline -> error_class timeout", body.get("error_class") == "timeout", str(body))

        # ---- malformed body -> bad_input ----
        status, raw = _http(port, "POST", "/invoke", b"{not valid json", timeout=15)
        body = json.loads(raw)
        check("malformed body -> 500", status == 500, f"status={status}")
        check("malformed body -> error_class bad_input", body.get("error_class") == "bad_input", str(body))

        print()
        print(f"ALL PASSED ({PASSED} checks)")
    finally:
        _cleanup()
        shutil.rmtree(workdir_host, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print()
        print(f"FAILED: {exc}")
        _cleanup()
        sys.exit(1)
