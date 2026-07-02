"""CAS client tests against a stub PEP that enforces the real auth contract:
it rebuilds the canonical string from the request and verifies the Ed25519 PoP
signature, verifies hashes on write, and replays the PEP's status codes."""

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from nacl.signing import SigningKey, VerifyKey

from dispatch_client.cas import (
    CasAuthError,
    CasClient,
    CasIntegrityError,
    CasNotFound,
    Credential,
    compute_address,
    validate_address,
)


class StubPep(ThreadingHTTPServer):
    """A minimal PEP: PoP-verified blob store in a dict."""

    def __init__(self, verify_key: VerifyKey):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.blobs: dict[str, bytes] = {}
        self.verify_key = verify_key
        self.corrupt_reads = False  # when True, GET returns flipped bytes


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: StubPep

    def _deny(self, status, msg):
        body = msg.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        """Rebuild the canonical string and verify the PoP, like the real PEP."""
        try:
            nonce = self.headers["X-Dispatch-Nonce"]
            ts = self.headers["X-Dispatch-Ts"]
            sig = base64.b64decode(self.headers["X-Dispatch-Pop"])
            if not self.headers.get("X-Dispatch-Biscuit"):
                return False
            canonical = f"cas/v0 {self.command} {self.path} {nonce} {ts}"
            self.server.verify_key.verify(canonical.encode(), sig)
            return True
        except Exception:
            return False

    def _hexaddr(self):
        prefix = "/blobs/sha256/"
        if not self.path.startswith(prefix):
            return None
        rest = self.path[len(prefix) :]
        return rest if len(rest) == 64 else None

    def do_GET(self):
        if not self._authed():
            return self._deny(401, "unauthenticated")
        hexaddr = self._hexaddr()
        if hexaddr is None or hexaddr not in self.server.blobs:
            return self._deny(404, "not_found")
        data = self.server.blobs[hexaddr]
        if self.server.corrupt_reads:
            data = b"X" + data[1:] if data else b"X"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        if not self._authed():
            return self._deny(401, "unauthenticated")
        hexaddr = self._hexaddr()
        if hexaddr is None or hexaddr not in self.server.blobs:
            return self._deny(404, "not_found")
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.server.blobs[hexaddr])))
        self.end_headers()

    def do_PUT(self):
        if not self._authed():
            return self._deny(401, "unauthenticated")
        hexaddr = self._hexaddr()
        if hexaddr is None:
            return self._deny(404, "not_found")
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0:
            return self._deny(400, "content_length_required")
        data = self.rfile.read(length)
        if hashlib.sha256(data).hexdigest() != hexaddr:
            return self._deny(400, "hash_mismatch")
        created = hexaddr not in self.server.blobs
        self.server.blobs[hexaddr] = data
        self._deny(201 if created else 200, "ok")

    def log_message(self, *args):
        pass


@pytest.fixture()
def pep():
    key = SigningKey.generate()
    server = StubPep(key.verify_key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cred = Credential(
        biscuit="stub-biscuit",
        pubkey_hex=key.verify_key.encode().hex(),
        seed_b64=base64.b64encode(key.encode()).decode(),
    )
    client = CasClient(f"http://127.0.0.1:{server.server_address[1]}", cred)
    yield server, client
    server.shutdown()
    server.server_close()


def test_put_get_roundtrip(pep):
    server, client = pep
    addr = client.put(b"hello cas")
    assert addr == compute_address(b"hello cas")
    assert client.get(addr) == b"hello cas"
    assert client.head(addr) == len(b"hello cas")


def test_put_idempotent(pep):
    _, client = pep
    a1 = client.put(b"same bytes")
    a2 = client.put(b"same bytes")
    assert a1 == a2


def test_get_missing_raises_not_found(pep):
    _, client = pep
    missing = "sha256:" + "0" * 64
    with pytest.raises(CasNotFound):
        client.get(missing)
    assert client.head(missing) is None


def test_verify_on_read_rejects_corruption(pep):
    server, client = pep
    addr = client.put(b"important data")
    server.corrupt_reads = True
    with pytest.raises(CasIntegrityError):
        client.get(addr)


def test_bad_signature_is_denied(pep):
    server, _ = pep
    # A client with a DIFFERENT key than the one the server trusts.
    other = SigningKey.generate()
    cred = Credential(
        biscuit="stub-biscuit",
        pubkey_hex=other.verify_key.encode().hex(),
        seed_b64=base64.b64encode(other.encode()).decode(),
    )
    rogue = CasClient(f"http://127.0.0.1:{server.server_address[1]}", cred)
    with pytest.raises(CasAuthError):
        rogue.put(b"anything")


def test_file_streaming_roundtrip(pep, tmp_path):
    _, client = pep
    src = tmp_path / "audio.bin"
    payload = bytes(range(256)) * 4096  # 1 MiB
    src.write_bytes(payload)
    known_hex = hashlib.sha256(payload).hexdigest()

    addr = client.put_file(src, sha256_hex=known_hex)
    assert addr == f"sha256:{known_hex}"

    dest = tmp_path / "fetched.bin"
    n = client.get_to_file(addr, dest)
    assert n == len(payload)
    assert dest.read_bytes() == payload


def test_get_to_file_never_leaves_partial(pep, tmp_path):
    server, client = pep
    addr = client.put(b"will corrupt")
    server.corrupt_reads = True
    dest = tmp_path / "out.bin"
    with pytest.raises(CasIntegrityError):
        client.get_to_file(addr, dest)
    assert not dest.exists()
    assert not (tmp_path / "out.bin.casfetch").exists()


def test_put_file_wrong_claimed_hash_rejected(pep, tmp_path):
    _, client = pep
    src = tmp_path / "f.bin"
    src.write_bytes(b"actual bytes")
    from dispatch_client.cas import CasError

    with pytest.raises(CasError):
        client.put_file(src, sha256_hex="ab" * 32)  # a lie; store verifies


def test_put_json_is_canonical(pep):
    _, client = pep
    a1 = client.put_json({"b": 1, "a": [2, 3]})
    a2 = client.put_json({"a": [2, 3], "b": 1})
    assert a1 == a2
    assert client.get_json(a1) == {"a": [2, 3], "b": 1}


def test_validate_address_rejects_garbage():
    for bad in ["", "sha256:", "sha256:XYZ", "sha256:" + "A" * 64, "../../etc", None]:
        with pytest.raises((ValueError, TypeError)):
            validate_address(bad)  # type: ignore[arg-type]


def test_json_roundtrip_preserves_bytes(pep):
    _, client = pep
    obj = {
        "kind": "invocation/v0",
        "op": "transcribe",
        "op_version": 1,
        "params": {"model": "large-v3", "diarize": True},
        "inputs": {"audio": {"address": "sha256:" + "0" * 64, "kind": "blob"}},
    }
    addr = client.put_json(obj)
    raw = client.get(addr)
    assert json.loads(raw) == obj
    # Canonical form: rebuilding the same object yields the same address.
    assert client.put_json(json.loads(raw)) == addr
