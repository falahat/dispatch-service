"""Integration tests for DispatchClient against the REAL Go dispatcher.

Builds ``dispatcherd`` from source, starts it with a temp plane.toml on loopback
TCP, and drives the app surface through the Python client. Completions are
produced by connecting to the runner surface as a raw framed client
(hello -> lease -> complete) to push a job into PERSISTING.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

# Make the package importable when run from the client/ dir without an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dispatch_client import DispatchClient, DispatchError  # noqa: E402
from dispatch_client import frame  # noqa: E402

GO = os.environ.get("GO", "go")
REPO = Path(__file__).resolve().parents[2]  # dispatch-service/

# A valid CAS address is sha256: + 64 hex; the dispatcher never fetches it.
DUMMY_ADDR = "sha256:" + "ab" * 32


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} never came up")


class Dispatcher:
    """A built-and-running dispatcherd on temp ports/db, for one test."""

    def __init__(self, tmp: Path, binary: Path):
        self.app_port = _free_port()
        self.runner_port = _free_port()
        self.app_addr = f"127.0.0.1:{self.app_port}"
        self.runner_addr = f"127.0.0.1:{self.runner_port}"
        self._db = tmp / "dispatch.db"
        cfg = tmp / "plane.toml"
        cfg.write_text(
            "\n".join(
                [
                    f'db_path = "{self._db.as_posix()}"',
                    f'runner_listen = "{self.runner_addr}"',
                    f'app_listen = "{self.app_addr}"',
                    "lease_ttl_s = 300",
                    "sweep_interval_s = 1",
                    "",
                    "[budget]",
                    'cap_usd = "100.00"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self._proc = subprocess.Popen(
            [str(binary), "-config", str(cfg)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_port("127.0.0.1", self.app_port)
            _wait_for_port("127.0.0.1", self.runner_port)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)


@pytest.fixture(scope="session")
def dispatcher_binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("bin") / "dispatcherd.exe"
    subprocess.run(
        [
            GO,
            "-C",
            str(REPO),
            "build",
            "-o",
            str(out),
            "./dispatcher/cmd/dispatcherd",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert out.exists(), "go build produced no binary"
    return out


@pytest.fixture
def dispatcher(dispatcher_binary, tmp_path) -> Dispatcher:
    d = Dispatcher(tmp_path, dispatcher_binary)
    try:
        yield d
    finally:
        d.stop()


# --- raw runner-surface helper (pushes a job to PERSISTING) ---


class RawRunner:
    """A minimal framed runner client: hello -> lease -> complete."""

    def __init__(self, addr: str, lanes: list[str]):
        host, port = addr.split(":")
        self.sock = socket.create_connection((host, int(port)))
        self.lanes = lanes
        self._id = 0

    def _call(self, msg_type: str, body: dict) -> dict:
        self._id += 1
        frame.write_message(self.sock, f"r{self._id}", msg_type, body)
        return frame.read_message(self.sock)

    def hello(self, runner_id: str = "RUNNER1") -> None:
        env = self._call(
            "hello",
            {
                "contract": "0.1",
                "runner": {
                    "id": runner_id,
                    "version": "test/0.1",
                    "node": "test-node",
                    "lanes": self.lanes,
                    "capacity": 1,
                },
            },
        )
        assert env["type"] == "hello_ok", env

    def lease_and_complete(self, wait_s: int = 5) -> str:
        """Long-poll for a grant, then complete it. Returns the job_id."""
        env = self._call("lease", {"lanes": self.lanes, "wait_s": wait_s})
        assert env["type"] == "grant", env
        grant = env["body"]
        job = grant["job"]
        inv = job["invocation_address"]
        cres = self._call(
            "complete",
            {
                "lease_id": grant["lease"]["lease_id"],
                "job_id": job["job_id"],
                "attempt": job["attempt"],
                "action_result": {
                    "kind": "action_result/v0",
                    "invocation_address": inv,
                    "outputs": {},
                    "metrics": {},
                    "runner": {"node": "test-node", "version": "test/0.1"},
                },
            },
        )
        assert cres["type"] == "ok", cres
        return job["job_id"]

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --- tests ---


def test_enqueue_idempotency(dispatcher):
    with DispatchClient(dispatcher.app_addr) as client:
        job = {"job_key": "idem-1", "lane": "embed", "invocation_address": DUMMY_ADDR}

        first = client.enqueue([job])
        assert len(first) == 1
        assert first[0]["job_key"] == "idem-1"
        assert first[0]["created"] is True
        job_id = first[0]["job_id"]
        assert job_id.startswith("j_")

        # Same live job_key -> same job_id, created=False.
        second = client.enqueue([job])
        assert second[0]["created"] is False
        assert second[0]["job_id"] == job_id


def test_jobs_read(dispatcher):
    with DispatchClient(dispatcher.app_addr) as client:
        client.enqueue([{"job_key": "read-1", "lane": "embed", "invocation_address": DUMMY_ADDR}])
        res = client.jobs()
        keys = {j["job_key"] for j in res["jobs"]}
        assert "read-1" in keys

        # Filter by lane narrows the view.
        filtered = client.jobs(filter={"lane": "embed"})
        assert all(j["lane"] == "embed" for j in filtered["jobs"])
        assert any(j["job_key"] == "read-1" for j in filtered["jobs"])


def test_fleet_budget_sweep(dispatcher):
    with DispatchClient(dispatcher.app_addr) as client:
        assert isinstance(client.fleet(), list)
        assert isinstance(client.budget(), dict)
        assert isinstance(client.sweep(), dict)


def test_stats_drain_snapshot(dispatcher):
    """The drain-health verb: state counts, windowed events, oldest-queued age."""
    with DispatchClient(dispatcher.app_addr) as client:
        client.enqueue([{"job_key": "st-1", "lane": "embed", "invocation_address": DUMMY_ADDR}])
        view = client.stats()
        assert view["window_s"] == 900  # server default
        cells = {(j["lane"], j["state"]): j["count"] for j in view["jobs"]}
        assert cells[("embed", "QUEUED")] == 1
        # The enqueue itself is a settled event inside the window.
        events = {(a["lane"], a["outcome"]): a["count"] for a in view["attempts"]}
        assert events[("embed", "enqueue")] == 1
        assert view["recent_failures"] == []  # nothing failing
        assert view["oldest_queued_age_s"] >= 0

        # A caller-chosen window rides through.
        assert client.stats(window_s=60)["window_s"] == 60


def test_error_reply_raises(dispatcher):
    with DispatchClient(dispatcher.app_addr) as client:
        # A malformed address fails the enqueue with a per-request error.
        with pytest.raises(DispatchError) as exc:
            client.enqueue(
                [{"job_key": "bad-1", "lane": "embed", "invocation_address": "not-an-address"}]
            )
        assert exc.value.code  # carries a code
        assert exc.value.message


def test_completion_flows_and_ack_drains(dispatcher):
    with DispatchClient(dispatcher.app_addr) as client:
        client.enqueue([{"job_key": "comp-1", "lane": "embed", "invocation_address": DUMMY_ADDR}])

        # Push the job to PERSISTING via the raw runner surface.
        runner = RawRunner(dispatcher.runner_addr, ["embed"])
        runner.hello()
        job_id = runner.lease_and_complete()

        # completions() yields the persisting job; grab the first one.
        got: list[dict] = []
        gen = client.completions()

        def consume():
            for c in gen:
                got.append(c)
                break

        t = threading.Thread(target=consume, daemon=True)
        t.start()
        t.join(timeout=10)
        client.stop_completions()
        runner.close()

        assert got, "no completion received"
        comp = got[0]
        assert comp["job_id"] == job_id
        assert comp["job_key"] == "comp-1"
        assert comp["action_result"]["invocation_address"] == DUMMY_ADDR

        # Ack drains it from PERSISTING -> SUCCEEDED (on the request connection).
        client.ack(job_id, "persisted")
        succeeded = client.jobs(filter={"state": "SUCCEEDED"})
        assert any(j["job_id"] == job_id for j in succeeded["jobs"])

        # A fresh subscription no longer redelivers the acked job.
        redelivered: list[dict] = []
        gen2 = client.completions()

        def consume2():
            try:
                for c in gen2:
                    redelivered.append(c)
            except Exception:
                pass

        t2 = threading.Thread(target=consume2, daemon=True)
        t2.start()
        time.sleep(1.0)
        client.stop_completions()
        t2.join(timeout=5)
        assert all(c["job_id"] != job_id for c in redelivered)


def test_request_timeout_surfaces_instead_of_hanging():
    """A wedged server (accepts, never replies) must raise within the timeout, not hang.

    This is what lets a health poller call the app surface from a supervised loop: the
    read deadline turns a hung dispatcher into an error the caller can degrade on."""
    wedge = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wedge.bind(("127.0.0.1", 0))
    wedge.listen(2)  # both attempts (the client retries once on a fresh connection)
    port = wedge.getsockname()[1]
    try:
        with DispatchClient(f"127.0.0.1:{port}", timeout=0.5) as client:
            start = time.time()
            with pytest.raises(OSError):
                client.stats()
            # Two bounded attempts, not an unbounded block.
            assert time.time() - start < 5.0
    finally:
        wedge.close()


def test_subscription_takeover(dispatcher):
    """Two subscribe connections: the first receives a takeover frame."""
    host, port = dispatcher.app_addr.split(":")

    # First raw subscription connection.
    sub1 = socket.create_connection((host, int(port)))
    frame.write_message(sub1, "s1", "subscribe", {})
    time.sleep(0.2)  # let the server register sub1

    # Second subscription supersedes it.
    sub2 = socket.create_connection((host, int(port)))
    frame.write_message(sub2, "s2", "subscribe", {})

    sub1.settimeout(5)
    env = frame.read_message(sub1)
    assert env["type"] == "takeover", env

    sub1.close()
    sub2.close()
