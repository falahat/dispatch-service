"""run_step against the stub PEP of test_cas.py and a scripted app surface whose worker runs the
job when its log is first read: inputs go up once, the invocation carries argv and output names,
the log streams, outputs land in the destination and the job is acknowledged."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from dispatch_client.cas import CasClient, Credential
from dispatch_client.cli import _parser
from dispatch_client.run import Place, follow, run_step
from test_cas import StubPep


def _store(server: StubPep, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    server.blobs[digest] = data
    return "sha256:" + digest


class Plane:
    """The app verbs run_step uses. The job runs when its log is first read: the worker reads
    the invocation, writes one log chunk, a report file and a frames folder."""

    def __init__(self, server: StubPep, fail: bool = False, kept: dict[str, Any] | None = None):
        self.server = server
        self.fail = fail
        self.kept = kept
        self.jobs: list[dict[str, Any]] = []
        self.acked: list[str] = []
        self.invocation: dict[str, Any] = {}
        self.state = "QUEUED"
        self.result: dict[str, Any] = {}
        self.log = b"frames 0-59 done\n"

    def enqueue(self, jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.jobs.extend(jobs)
        return [{"job_key": jobs[0]["job_key"], "job_id": "j_TEST", "created": True}]

    def logs(self, job_id: str, after: int = 0, wait: bool = True) -> dict[str, Any]:
        if self.state == "QUEUED":
            address = self.jobs[-1]["invocation_address"]
            self.invocation = json.loads(self.server.blobs[address[7:]])
            self.state = "FAILED" if self.fail else "PERSISTING"
            frames = [
                {
                    "path": f"frame-{i}.bin",
                    "address": _store(self.server, bytes([i]) * 100),
                    "size": 100,
                }
                for i in range(3)
            ]
            manifest = json.dumps({"kind": "manifest/v0", "entries": frames}).encode()
            report = b'{"frames": 3}'
            self.result = {
                "kind": "action_result/v0",
                "invocation_address": address,
                "outputs": {
                    "report": {
                        "address": _store(self.server, report),
                        "size": len(report),
                        "kind": "blob",
                    },
                    "frames": {
                        "address": _store(self.server, manifest),
                        "size": len(manifest),
                        "kind": "manifest",
                    },
                },
                "metrics": {"exit": 0},
            }
            if self.kept:
                self.result["outputs"]["kept"] = self.kept
            chunk = {"offset": 0, "address": _store(self.server, self.log), "size": len(self.log)}
            return {"entries": [chunk], "next_offset": len(self.log), "done": False}
        return {"entries": [], "next_offset": after, "done": True}

    def job(self, job_id: str) -> dict[str, Any]:
        timeline = [
            {"attempt": 0, "outcome": "enqueue", "ts": 1_000},
            {"attempt": 1, "outcome": "claimed", "ts": 1_250},
            {"attempt": 1, "outcome": "fail" if self.fail else "complete", "ts": 4_250},
        ]
        view = {"job_id": job_id, "state": self.state, "timeline": timeline}
        if not self.fail:
            view["action_result"] = self.result
        return view

    def ack(self, job_id: str, disposition: str, reason: str | None = None) -> None:
        self.acked.append(disposition)
        self.state = "SUCCEEDED"


@pytest.fixture()
def pep():
    key = SigningKey.generate()
    server = StubPep(key.verify_key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    credential = Credential(
        biscuit="stub-biscuit",
        pubkey_hex=key.verify_key.encode().hex(),
        seed_b64=base64.b64encode(key.encode()).decode(),
    )
    yield server, CasClient(f"http://127.0.0.1:{server.server_address[1]}", credential)
    server.shutdown()
    server.server_close()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    video = tmp_path / "clip.mp4"
    video.write_bytes(bytes(range(256)) * 8192)  # 2 MiB: looked up before it is sent
    code = tmp_path / "code" / "scan"
    code.mkdir(parents=True, exist_ok=True)
    (code / "fit.py").write_text("print('fit')\n")
    return {"video": video, "code": tmp_path / "code"}


def test_run_step_uploads_runs_streams_and_fetches(pep, tmp_path):
    server, cas = pep
    plane = Plane(server)
    log: list[bytes] = []
    result = run_step(
        plane,  # type: ignore[arg-type]
        cas,
        lane="pose-prefit",
        argv=["python", "-m", "scan.fit", "/in/video"],
        inputs=_inputs(tmp_path),
        outputs=["report", "frames"],
        params={"window": "0-2"},
        gpu={"memory_mb": 8192, "mode": "shared"},
        dest=tmp_path / "out",
        log=log.append,
    )
    assert plane.invocation["params"] == {
        "window": "0-2",
        "argv": ["python", "-m", "scan.fit", "/in/video"],
        "outputs": ["report", "frames"],
    }
    assert {name: value["kind"] for name, value in plane.invocation["inputs"].items()} == {
        "code": "manifest",
        "video": "blob",
    }
    assert plane.jobs[0]["policy"] == {"gpu": {"memory_mb": 8192, "mode": "shared"}}
    assert plane.jobs[0]["lane"] == "pose-prefit"
    assert b"".join(log) == plane.log
    assert (tmp_path / "out" / "report").read_bytes() == b'{"frames": 3}'
    assert sorted(p.name for p in (tmp_path / "out" / "frames").iterdir()) == [
        "frame-0.bin",
        "frame-1.bin",
        "frame-2.bin",
    ]
    assert plane.acked == ["persisted"]
    assert result.ok and result.state == "SUCCEEDED"
    assert result.seconds["queued"] == 0.25 and result.seconds["run"] == 3.0
    assert result.bytes["uploaded"] >= 2 << 20 and result.bytes["already_stored"] == 0
    assert result.bytes["downloaded"] > 300

    again = Plane(server)
    second = run_step(
        again,  # type: ignore[arg-type]
        cas,
        lane="pose-prefit",
        argv=["python", "-m", "scan.fit", "/in/video"],
        inputs=_inputs(tmp_path),
        outputs=["report", "frames"],
        dest=tmp_path / "again",
        log=lambda data: None,
    )
    assert second.ok
    assert second.bytes["already_stored"] == 2 << 20
    assert second.bytes["uploaded"] < 4096


def test_local_inputs_are_read_in_place_and_local_outputs_stay(pep, tmp_path):
    server, cas = pep
    kept = {"kind": "local", "node": "bigboi", "root": "runs", "path": "K/fit", "size": 0}
    plane = Plane(server, kept=kept)
    result = run_step(
        plane,  # type: ignore[arg-type]
        cas,
        lane="pose",
        argv=["python", "-m", "scan.fit", "/in/run"],
        local={"run": Place.parse("bigboi:runs/K")},
        outputs=["report"],
        dest=tmp_path / "out",
        log=lambda data: None,
    )
    assert plane.invocation["inputs"] == {
        "run": {"kind": "local", "node": "bigboi", "root": "runs", "path": "K"}
    }
    assert plane.jobs[0]["policy"] == {"node": "bigboi"}
    assert result.ok and result.local == {"kept": Place("bigboi", "runs", "K/fit")}
    assert result.summary()["local"] == {"kept": "bigboi:runs/K/fit"}
    assert not (tmp_path / "out" / "kept").exists()
    assert result.bytes["uploaded"] < 1024  # the invocation alone


@pytest.mark.parametrize(
    "text", ["bigboi:runs", "bigboi/runs/K", ":runs/K", "bigboi:Runs/K", "bigboi:runs/../K"]
)
def test_bad_places_are_refused(text):
    with pytest.raises(ValueError):
        Place.parse(text)


def test_failed_job_returns_without_outputs_or_ack(pep, tmp_path):
    server, cas = pep
    plane = Plane(server, fail=True)
    plane.jobs.append({"invocation_address": cas.put_json({"kind": "invocation/v0"})})
    result = follow(plane, cas, "j_TEST", tmp_path / "out", log=lambda data: None)  # type: ignore[arg-type]
    assert result.state == "FAILED" and not result.ok
    assert result.outputs == {} and plane.acked == []
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"params": {"scale": 0.5}},
        {"params": {"argv": ["x"]}},
        {"outputs": ["Report"]},
        {"argv": []},
        {"local": {"a": Place("n1", "runs", "x"), "b": Place("n2", "runs", "y")}},
        {"local": {"a": Place("n1", "runs", "x")}, "node": "n2"},
        {"local": {"a": Place("n1", "runs", "x/./y")}},
    ],
)
def test_bad_run_requests_fail_before_queueing(pep, tmp_path, change):
    server, cas = pep
    plane = Plane(server)
    request: dict[str, Any] = {"lane": "pose-prefit", "argv": ["python"], "outputs": ["report"]}
    with pytest.raises(ValueError):
        run_step(plane, cas, **{**request, **change})  # type: ignore[arg-type]
    assert plane.jobs == []


def test_run_command_keeps_the_whole_argv():
    args = vars(
        _parser().parse_args(
            [
                "-addr",
                "unix:/x",
                "run",
                "--lane",
                "l",
                "--input",
                "v=a.mp4",
                "--local",
                "run=bigboi:runs/K",
                "--",
                "python",
                "-m",
                "scan.fit",
                "--lane",
                "other",
            ]
        )
    )
    argv = args["argv"][1:] if args["argv"][:1] == ["--"] else args["argv"]
    assert argv == ["python", "-m", "scan.fit", "--lane", "other"]
    assert args["input"] == ["v=a.mp4"] and args["lane"] == "l"
    assert args["local"] == ["run=bigboi:runs/K"] and args["node"] is None
