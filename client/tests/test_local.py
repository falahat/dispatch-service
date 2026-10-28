"""Exercise the real local dispatcher, runner, command and Python client together."""

import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from dispatch_client import DispatchClient
from dispatch_client import frame


@unittest.skipUnless(os.environ.get("DISPATCH_LOCAL_BIN"), "needs built dispatch-local")
class LocalCommands(unittest.TestCase):
    def test_lost_submission_reply_is_not_replayed(self) -> None:
        for retry, expected in ((False, 1), (True, 2)):
            with (
                tempfile.TemporaryDirectory() as directory,
                socket.socket(socket.AF_UNIX) as listener,
            ):
                address = str(Path(directory) / "server.sock")
                listener.bind(address)
                listener.listen()
                stop, stopped = socket.socketpair()
                requests = []

                def server() -> None:
                    while True:
                        readable, _, _ = select.select([listener, stopped], [], [])
                        if listener in readable:
                            with listener.accept()[0] as connection:
                                requests.append(frame.read_message(connection))
                                # The authoritative side got the request; its reply is lost.
                        if stopped in readable:
                            return

                thread = threading.Thread(target=server)
                thread.start()
                client = DispatchClient("unix:" + address, retry_requests=retry)
                try:
                    with self.assertRaises(ConnectionError):
                        client.enqueue([])
                finally:
                    client.close()
                    stop.sendall(b"x")
                    thread.join()
                    stop.close()
                    stopped.close()
                self.assertEqual(len(requests), expected)

    def test_dedup_concurrent_wait_cancel_and_no_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "capacity").write_text("1\n")
            (root / "plane.toml").write_text(
                "heartbeat_interval_s=1\nlease_ttl_s=30\n"
                "runner_rate_per_min=0\n[default_lane]\nsingle_attempt=true\n"
            )
            script = root / "executor.py"
            script.write_text(
                "import json,os,signal,socket,sys\n"
                "request=json.load(sys.stdin)\n"
                "assert request['deadline_ts']==0\n"
                "params=request['invocation']['params']\n"
                "def cancel(*unused):\n"
                " open(params['cleanup'],'w').write('settled')\n"
                " sys.exit(0)\n"
                "signal.signal(signal.SIGTERM,cancel)\n"
                "connection=socket.socket(socket.AF_UNIX)\n"
                "connection.connect(params['ready'])\n"
                "connection.sendall((str(os.getpid())+'\\n').encode())\n"
                "connection.recv(1)\n"
                "if params['fail']: sys.exit(7)\n"
                "with open('invoke-result.json','w') as output:\n"
                " json.dump({'outputs':{},'metrics':{'exit':0}},output)\n"
            )
            notification = self.enterContext(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
            notification.bind(str(root / "notify.sock"))
            daemon = subprocess.Popen(
                [
                    os.environ["DISPATCH_LOCAL_BIN"],
                    "--root",
                    str(root / "queue"),
                    "--config",
                    str(root / "plane.toml"),
                    "--workers-file",
                    str(root / "capacity"),
                    "--no-deadline",
                    "--reserve-lane",
                    "isolated",
                    "--",
                    sys.executable,
                    str(script),
                ],
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, "NOTIFY_SOCKET": str(root / "notify.sock")},
            )
            assert daemon.stderr is not None
            try:
                while True:
                    readable, _, _ = select.select([notification, daemon.stderr], [], [])
                    if notification in readable:
                        self.assertEqual(notification.recv(64), b"READY=1")
                        break
                    self.assertTrue(daemon.stderr.readline(), "local queue failed before readiness")
                client = DispatchClient(
                    "unix:" + str(root / "queue/app.sock"), retry_requests=False
                )
                self.addCleanup(client.close)
                for outcome in ("complete", "cancel", "fail"):
                    with socket.socket(socket.AF_UNIX) as ready:
                        address = root / (outcome + ".sock")
                        ready.bind(str(address))
                        ready.listen(1)
                        invocation = json.dumps(
                            {
                                "kind": "invocation/v0",
                                "op": "command",
                                "op_version": 1,
                                "params": {
                                    "ready": str(address),
                                    "cleanup": str(root / "cleaned"),
                                    "fail": outcome == "fail",
                                },
                                "inputs": {},
                            }
                        ).encode()
                        digest = hashlib.sha256(invocation).hexdigest()
                        blob = root / "queue/cas/blobs/sha256" / digest
                        blob.parent.mkdir(parents=True, exist_ok=True)
                        blob.write_bytes(invocation)
                        request = {
                            "job_key": outcome,
                            "lane": "work",
                            "invocation_address": "sha256:" + digest,
                        }
                        submitted = client.enqueue([request])[0]
                        with ready.accept()[0] as execution:
                            pid = int(execution.recv(64))
                            twin = client.enqueue([request])[0]
                            self.assertFalse(twin["created"])
                            self.assertEqual(twin["job_id"], submitted["job_id"])
                            if outcome == "complete":
                                with socket.socket(socket.AF_UNIX) as reserved:
                                    reserved.bind(str(root / "reserved.sock"))
                                    reserved.listen(1)
                                    separate = json.loads(invocation)
                                    separate["params"]["ready"] = str(root / "reserved.sock")
                                    raw = json.dumps(separate).encode()
                                    digest = hashlib.sha256(raw).hexdigest()
                                    (blob.parent / digest).write_bytes(raw)
                                    special = client.enqueue(
                                        [
                                            {
                                                "job_key": "reserved",
                                                "lane": "isolated",
                                                "invocation_address": "sha256:" + digest,
                                            }
                                        ]
                                    )[0]
                                    with reserved.accept()[0] as concurrent:
                                        concurrent.recv(64)
                                        concurrent.sendall(b"x")
                                    self.assertEqual(
                                        client.wait(special["job_id"])["state"], "SUCCEEDED"
                                    )
                            results = []

                            def wait() -> None:
                                results.append(client.wait(submitted["job_id"]))

                            observers = [threading.Thread(target=wait) for _ in range(2)]
                            for observer in observers:
                                observer.start()
                            if outcome == "cancel":
                                client.cancel(submitted["job_id"], "test cancellation")
                            else:
                                execution.sendall(b"x")
                            for observer in observers:
                                observer.join()
                            self.assertEqual(len(results), 2)
                            expected = {
                                "complete": "SUCCEEDED",
                                "cancel": "CANCELLED",
                                "fail": "FAILED",
                            }[outcome]
                            self.assertTrue(
                                all(result["state"] == expected for result in results),
                                (outcome, expected, results),
                            )
                            if outcome == "complete":
                                self.assertTrue(results[0]["action_result"]["runner"]["version"])
                            self.assertEqual(client.job(submitted["job_id"])["attempt"], 1)
                            if outcome == "cancel":
                                self.assertEqual((root / "cleaned").read_text(), "settled")
                                with self.assertRaises(ProcessLookupError):
                                    os.kill(pid, 0)
            finally:
                daemon.terminate()
                daemon.wait()
                daemon.stderr.close()
