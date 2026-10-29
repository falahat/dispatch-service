"""The standard network dispatcher and runner execute an installed command."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from dispatch_client import DispatchClient


@unittest.skipUnless(os.environ.get("DISPATCHER_BIN"), "needs built native binaries")
class CommandWorkers(unittest.TestCase):
    def test_native_results_logs_cancellation_and_no_retry(self) -> None:
        blobs = {}

        class Store(BaseHTTPRequestHandler):
            def respond(self, body: bool = True) -> None:
                data = blobs.get(self.path)
                self.send_response(404 if data is None else 200)
                self.send_header("Content-Length", str(len(data or b"")))
                self.end_headers()
                if body and data is not None:
                    self.wfile.write(data)

            def do_HEAD(self) -> None:
                self.respond(False)

            def do_GET(self) -> None:
                self.respond()

            def do_PUT(self) -> None:
                blobs[self.path] = self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *unused: object) -> None:
                pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ThreadingHTTPServer(("127.0.0.1", 0), Store)
            thread = threading.Thread(target=store.serve_forever)
            thread.start()
            self.addCleanup(store.server_close)
            self.addCleanup(thread.join)
            self.addCleanup(store.shutdown)
            cas_url = f"http://127.0.0.1:{store.server_port}"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = root / "plane.toml"
            config.write_text(
                f'db_path="{root}/queue.db"\nrunner_listen="127.0.0.1:{port}"\n'
                f'app_socket="{root}/app.sock"\napp_listen=""\n'
                "heartbeat_interval_s=1\nlease_ttl_s=30\nrunner_rate_per_min=0\n"
                "wait_for_executor=true\n[default_lane]\nsingle_attempt=true\n"
            )
            script = root / "execute.py"
            script.write_text(
                "import json,os,signal,socket,sys\n"
                "request=json.load(sys.stdin)\n"
                "assert request['deadline_ts']==0\n"
                "params=request['invocation']['params']\n"
                "def finish(code):\n"
                " with open('invoke-result.json','w') as out:\n"
                "  json.dump({'outputs':{},'metrics':{'exit':code}},out)\n"
                "def cancel(*unused):\n"
                " open(params['cleanup'],'w').write('settled')\n"
                " finish(137); sys.exit(0)\n"
                "signal.signal(signal.SIGTERM,cancel)\n"
                "print('live command output',flush=True)\n"
                "connection=socket.socket(socket.AF_UNIX)\n"
                "connection.connect(params['ready'])\n"
                "connection.sendall((str(os.getpid())+'\\n').encode())\n"
                "connection.recv(1)\n"
                "if params['fail']: sys.exit(7)\n"
                "print('final command output',flush=True); finish(0)\n"
            )
            daemon = subprocess.Popen(
                [os.environ["DISPATCHER_BIN"], "-config", str(config)],
                stderr=subprocess.PIPE,
                text=True,
            )
            worker = None
            pep = None
            assert daemon.stderr is not None
            try:
                while True:
                    line = daemon.stderr.readline()
                    self.assertTrue(line, "dispatcher exited before readiness")
                    if json.loads(line).get("msg") == "dispatcher serving":
                        break
                credentials = ["--id", "native-worker"]
                endpoint = f"127.0.0.1:{port}"
                if os.environ.get("PEP_BIN"):
                    signer = [os.environ["SIGNER_BIN"], "-secrets", str(root / "issuer.json")]
                    root_key = subprocess.check_output(signer + ["pubkey"], text=True).strip()
                    credential = root / "worker.json"
                    public = subprocess.check_output(
                        [os.environ["RUNNER_BIN"], "keygen", "--out", str(credential)], text=True
                    ).strip()
                    capability = subprocess.check_output(
                        signer
                        + [
                            "enroll",
                            "--pubkey",
                            public,
                            "--rights",
                            "hello,lease,heartbeat,complete,fail,release,cas_get,cas_put",
                            "--lanes",
                            "build",
                        ]
                    )
                    subprocess.run(
                        [
                            os.environ["RUNNER_BIN"],
                            "seal",
                            "--cred",
                            str(credential),
                            "--biscuit-file",
                            "-",
                        ],
                        input=capability,
                        check=True,
                    )
                    with socket.socket() as runner_port, socket.socket() as cas_port:
                        runner_port.bind(("127.0.0.1", 0))
                        cas_port.bind(("127.0.0.1", 0))
                        endpoint = f"127.0.0.1:{runner_port.getsockname()[1]}"
                        cas_endpoint = f"127.0.0.1:{cas_port.getsockname()[1]}"
                    pep = subprocess.Popen(
                        [os.environ["PEP_BIN"]],
                        stderr=subprocess.PIPE,
                        text=True,
                        env={
                            **os.environ,
                            "PEP_ROOT_PUBKEY": root_key,
                            "PEP_RUNNER_LISTEN": endpoint,
                            "PEP_DISPATCHER_ADDR": f"127.0.0.1:{port}",
                            "PEP_CAS_LISTEN": cas_endpoint,
                            "PEP_CAS_BACKEND": cas_url,
                            "PEP_NONCE_DB": str(root / "nonces.redb"),
                            "PEP_REVOCATION_DB": str(root / "revocations.json"),
                        },
                    )
                    assert pep.stderr is not None
                    for surface in ("runner", "cas"):
                        while True:
                            line = pep.stderr.readline()
                            self.assertTrue(line, "PEP exited before readiness")
                            if f"pep: {surface} surface" in line:
                                break
                    cas_url = "http://" + cas_endpoint
                    credentials = ["--credential", str(credential)]
                    cas = [
                        os.environ["RUNNER_BIN"],
                        "cas",
                        "--url",
                        cas_url,
                        "--credential",
                        str(credential),
                    ]
                    uploaded = subprocess.check_output(
                        cas + ["put", str(script)], text=True
                    ).strip()
                    subprocess.run(
                        cas
                        + [
                            "--max-bytes",
                            str(script.stat().st_size),
                            "get",
                            uploaded,
                            str(root / "downloaded"),
                        ],
                        check=True,
                    )
                    self.assertEqual((root / "downloaded").read_bytes(), script.read_bytes())
                worker = subprocess.Popen(
                    [
                        os.environ["RUNNER_BIN"],
                        "run",
                        *credentials,
                        "--node",
                        "native-node",
                        "--dispatcher",
                        endpoint,
                        "--cas",
                        cas_url,
                        "--lanes",
                        "build",
                        "--work",
                        str(root / "work"),
                        "--no-deadline",
                        "--",
                        sys.executable,
                        str(script),
                    ],
                    stderr=subprocess.DEVNULL,
                )
                with DispatchClient(
                    "unix:" + str(root / "app.sock"), retry_requests=False
                ) as client:
                    for outcome in ("complete", "cancel", "fail"):
                        with socket.socket(socket.AF_UNIX) as ready:
                            path = root / (outcome + ".sock")
                            ready.bind(str(path))
                            ready.listen(1)
                            raw = json.dumps(
                                {
                                    "kind": "invocation/v0",
                                    "op": "command",
                                    "op_version": 1,
                                    "params": {
                                        "ready": str(path),
                                        "cleanup": str(root / "cleaned"),
                                        "fail": outcome == "fail",
                                    },
                                    "inputs": {},
                                }
                            ).encode()
                            address = "sha256:" + hashlib.sha256(raw).hexdigest()
                            blobs["/blobs/sha256/" + address[7:]] = raw
                            request = {
                                "job_key": outcome,
                                "lane": "build",
                                "invocation_address": address,
                            }
                            job = client.enqueue([request])[0]["job_id"]
                            with ready.accept()[0] as execution:
                                pid = int(execution.recv(64))
                                self.assertFalse(client.enqueue([request])[0]["created"])
                                log = client.logs(job)
                                chunk = log["entries"][0]
                                self.assertEqual(
                                    blobs["/blobs/sha256/" + chunk["address"][7:]],
                                    b"live command output\n",
                                )
                                if outcome == "cancel":
                                    client.cancel(job, "test cancellation")
                                else:
                                    execution.sendall(b"x")
                                if outcome != "fail":
                                    completion = next(client.completions())
                                    self.assertEqual(completion["job_id"], job)
                                    self.assertEqual(
                                        completion["action_result"]["metrics"]["exit"],
                                        137 if outcome == "cancel" else 0,
                                    )
                                    self.assertEqual(
                                        completion["action_result"]["runner"]["node"], "native-node"
                                    )
                                    client.ack(job, "persisted")
                                result = client.wait(job)
                                self.assertEqual(
                                    result["state"],
                                    {
                                        "complete": "SUCCEEDED",
                                        "cancel": "CANCELLED",
                                        "fail": "FAILED",
                                    }[outcome],
                                )
                                self.assertEqual(result["attempt"], 1)
                                if outcome == "cancel":
                                    self.assertEqual((root / "cleaned").read_text(), "settled")
                                    with self.assertRaises(ProcessLookupError):
                                        os.kill(pid, 0)
            finally:
                if worker is not None:
                    worker.terminate()
                    worker.wait()
                if pep is not None:
                    pep.terminate()
                    pep.wait()
                    pep.stderr.close()
                daemon.terminate()
                daemon.wait()
                daemon.stderr.close()
