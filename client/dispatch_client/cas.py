"""The app-side CAS client: authenticated, streaming, verify-on-read/write.

Speaks the PEP's blob surface (contracts/CAS.md): ``GET/HEAD/PUT
/blobs/sha256/<hex>`` with Biscuit + proof-of-possession headers. Every request
signs the canonical string ``cas/v0 <METHOD> <path> <nonce> <ts>`` with the
credential's Ed25519 key (PyNaCl), so a stolen token alone is useless.

Address rules enforced here (the artifacts contract):

* validate address shape before any use;
* verify-on-read — every GET re-hashes and compares (trust lives in the
  address, not the store);
* verify-on-write is the PEP/store's job, but ``put`` computes the address
  from the bytes it sends, so a mismatch is impossible by construction.

Blobs can be large (episode audio), so file transfers stream in both
directions; whole-blob buffering happens only in the convenience byte APIs.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urlsplit

_ADDRESS_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHUNK = 1 << 20  # 1 MiB streaming chunk
_MAX_MANIFEST_ENTRIES = 65536  # artifacts contract
_MAX_PATH_BYTES = 512  # artifacts contract


class CasError(Exception):
    """A CAS request failed. ``status`` is the HTTP status (0 = transport)."""

    def __init__(self, status: int, message: str):
        super().__init__(f"cas: {status}: {message}")
        self.status = status
        self.message = message


class CasAuthError(CasError):
    """The PEP denied the request (401/403)."""


class CasNotFound(CasError):
    """The blob does not exist (404)."""


class CasIntegrityError(CasError):
    """Fetched bytes did not hash to the requested address (verify-on-read)."""

    def __init__(self, address: str):
        super().__init__(0, f"integrity: bytes do not match {address}")


def compute_address(data: bytes) -> str:
    """The canonical CAS address of a byte string."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def validate_address(address: str) -> str:
    """Validate an address's shape (an address is data, never a path fragment).

    Returns the 64-hex digest. Raises ``ValueError`` on a malformed address.
    """
    if not isinstance(address, str) or not _ADDRESS_RE.match(address):
        raise ValueError(f"malformed CAS address: {address!r}")
    return address[len("sha256:") :]


@dataclass(frozen=True)
class Credential:
    """An identity's credential: the Biscuit token, the Ed25519 public key it
    binds (hex), and the 32-byte private seed proving possession (base64).
    Matches the runner's on-disk ``cred.json``."""

    biscuit: str
    pubkey_hex: str
    seed_b64: str

    @classmethod
    def load(cls, path: str | Path) -> "Credential":
        """Load a credential file: ``{"biscuit", "pubkey_hex", "seed_b64"}``."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        try:
            cred = cls(
                biscuit=str(raw["biscuit"]),
                pubkey_hex=str(raw["pubkey_hex"]),
                seed_b64=str(raw["seed_b64"]),
            )
        except KeyError as e:
            raise ValueError(f"credential file {path}: missing {e}") from None
        if not cred.biscuit or not cred.pubkey_hex or not cred.seed_b64:
            raise ValueError(f"credential file {path}: incomplete")
        return cred


class _PopSigner:
    """Signs canonical request strings with the credential's Ed25519 seed."""

    def __init__(self, cred: Credential):
        from nacl.signing import SigningKey  # the one non-stdlib dep, kept local

        seed = base64.b64decode(cred.seed_b64)
        if len(seed) != 32:
            raise ValueError("credential seed must be 32 bytes")
        self._key = SigningKey(seed)
        self._cred = cred

    def headers(self, method: str, path: str) -> dict[str, str]:
        """The auth headers for one request (fresh nonce + timestamp)."""
        nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        ts = int(time.time() * 1000)
        canonical = f"cas/v0 {method} {path} {nonce} {ts}"
        sig = self._key.sign(canonical.encode("utf-8")).signature
        return {
            "X-Dispatch-Biscuit": self._cred.biscuit,
            "X-Dispatch-Pubkey": self._cred.pubkey_hex,
            "X-Dispatch-Nonce": nonce,
            "X-Dispatch-Ts": str(ts),
            "X-Dispatch-Pop": base64.b64encode(sig).decode("ascii"),
        }


class CasClient:
    """A client for the PEP's CAS surface.

    ``base_url`` is the PEP's CAS address, e.g. ``http://pep:8443``. Each
    request opens a fresh connection (blob transfers are long; connection reuse
    buys little and complicates retry semantics).
    """

    def __init__(self, base_url: str, credential: Credential, timeout: float = 300.0):
        parts = urlsplit(base_url)
        if parts.scheme != "http" or not parts.netloc:
            raise ValueError(f"cas base_url must be http://host:port, got {base_url!r}")
        self._host = parts.hostname or ""
        self._port = parts.port or 80
        self._timeout = timeout
        self._signer = _PopSigner(credential)

    # --- connections ---

    def _conn(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    @staticmethod
    def _blob_path(address: str) -> str:
        return f"/blobs/sha256/{validate_address(address)}"

    @staticmethod
    def _raise_for(status: int, body: str) -> None:
        if status in (401, 403):
            raise CasAuthError(status, body)
        if status == 404:
            raise CasNotFound(status, body)
        raise CasError(status, body)

    # --- reads ---

    def head(self, address: str) -> Optional[int]:
        """Blob existence check. Returns its size, or ``None`` when absent."""
        path = self._blob_path(address)
        conn = self._conn()
        try:
            conn.request("HEAD", path, headers=self._signer.headers("HEAD", path))
            resp = conn.getresponse()
            resp.read()
            if resp.status == 404:
                return None
            if resp.status != 200:
                self._raise_for(resp.status, resp.reason or "")
            length = resp.getheader("Content-Length")
            return int(length) if length is not None else 0
        finally:
            conn.close()

    def get(self, address: str) -> bytes:
        """Fetch a blob fully into memory, verifying on read."""
        h = hashlib.sha256()
        chunks: list[bytes] = []

        def collect(block: bytes) -> None:
            h.update(block)
            chunks.append(block)

        self._stream_get(address, collect)
        if "sha256:" + h.hexdigest() != address:
            raise CasIntegrityError(address)
        return b"".join(chunks)

    def get_to_file(self, address: str, dest: str | Path) -> int:
        """Stream a blob to ``dest``, verifying on read.

        Writes to a temp sibling and renames only after the hash checks out, so
        a partial or corrupt fetch is never visible at ``dest``. Returns the
        byte count.
        """
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".casfetch")
        h = hashlib.sha256()
        total = 0
        try:
            with tmp.open("wb") as fh:

                def sink(b: bytes) -> None:
                    nonlocal total
                    h.update(b)
                    fh.write(b)
                    total += len(b)

                self._stream_get(address, sink)
            if "sha256:" + h.hexdigest() != address:
                raise CasIntegrityError(address)
            os.replace(tmp, dest)
            return total
        finally:
            tmp.unlink(missing_ok=True)

    def _stream_get(self, address: str, sink: Callable[[bytes], None]) -> None:
        path = self._blob_path(address)
        conn = self._conn()
        try:
            conn.request("GET", path, headers=self._signer.headers("GET", path))
            resp = conn.getresponse()
            if resp.status != 200:
                body = resp.read(4096).decode("utf-8", "replace")
                self._raise_for(resp.status, body)
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                sink(chunk)
        finally:
            conn.close()

    # --- writes ---

    def put(self, data: bytes) -> str:
        """Store bytes; returns their address. Idempotent (same bytes, same
        address, PUT of an existing blob is a no-op)."""
        address = compute_address(data)
        path = self._blob_path(address)
        headers = self._signer.headers("PUT", path)
        headers["Content-Length"] = str(len(data))
        conn = self._conn()
        try:
            conn.request("PUT", path, body=data, headers=headers)
            resp = conn.getresponse()
            body = resp.read(4096).decode("utf-8", "replace")
            if resp.status not in (200, 201):
                self._raise_for(resp.status, body)
            return address
        finally:
            conn.close()

    def put_file(self, src: str | Path, sha256_hex: Optional[str] = None) -> str:
        """Stream a file into the CAS; returns its address.

        ``sha256_hex`` (when the caller already knows the content hash, as the
        app does for episode audio) skips the pre-hash pass; the PEP/store still
        verifies on write, so a wrong claim is rejected, never stored.
        """
        return self._put_sized(Path(src), sha256_hex)[0]

    def _put_sized(self, src: Path, sha256_hex: Optional[str]) -> tuple[str, int]:
        """``put_file`` that also returns the byte count the store verified."""
        size = src.stat().st_size
        if sha256_hex is None:
            h = hashlib.sha256()
            with src.open("rb") as fh:
                for chunk in iter(lambda: fh.read(_CHUNK), b""):
                    h.update(chunk)
            sha256_hex = h.hexdigest()
        address = f"sha256:{sha256_hex}"
        path = self._blob_path(address)  # validates shape
        headers = self._signer.headers("PUT", path)
        headers["Content-Length"] = str(size)
        conn = self._conn()
        try:
            with src.open("rb") as fh:
                conn.request("PUT", path, body=fh, headers=headers)
                resp = conn.getresponse()
                body = resp.read(4096).decode("utf-8", "replace")
                if resp.status not in (200, 201):
                    self._raise_for(resp.status, body)
            return address, size
        finally:
            conn.close()

    def put_json(self, obj: Any) -> str:
        """Store an object as canonical JSON (sorted keys, tight separators) —
        the app-side canonicalization SHOULD that keeps invocation addresses
        stable across rebuilds. Returns the address."""
        data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.put(data)

    def get_json(self, address: str) -> Any:
        """Fetch + verify a blob and parse it as JSON."""
        return json.loads(self.get(address).decode("utf-8"))

    # --- folders (manifest/v0) ---

    def put_folder(self, src: str | Path) -> str:
        """Store a folder's regular files and a ``manifest/v0`` naming them,
        sorted by path; returns the manifest's address, for a ``manifest`` input.

        Links and special files raise ``ValueError`` before anything uploads, so
        a manifest names exactly the folder's own files.
        """
        files = sorted(_regular_files(Path(src), ""))
        if len(files) > _MAX_MANIFEST_ENTRIES:
            raise ValueError(f"{src}: more than {_MAX_MANIFEST_ENTRIES} files")
        entries = []
        for rel, path in files:
            address, size = self._put_sized(path, None)
            entries.append({"path": rel, "address": address, "size": size})
        return self.put_json({"kind": "manifest/v0", "entries": entries})

    def get_folder(self, address: str, dest: str | Path) -> int:
        """Fetch a manifest and every file it names into the new folder ``dest``;
        returns the file count.

        The tree is built in a temp sibling and renamed to ``dest`` only after
        every path is checked and every file verified, so ``dest`` never holds a
        partial tree or a file placed outside it.
        """
        dest = Path(dest)
        if dest.exists():
            raise FileExistsError(f"{dest} already exists")
        entries = _manifest_entries(self.get_json(address))
        dest.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=dest.name + ".", suffix=".casfetch", dir=dest.parent)
        )
        try:
            placed: set[Path] = set()
            for entry in entries:
                target = _entry_target(staging, entry["path"])
                if target in placed:
                    raise ValueError(f"manifest names {entry['path']!r} twice")
                placed.add(target)
                if self.get_to_file(entry["address"], target) != entry["size"]:
                    raise ValueError(f"manifest size of {entry['path']!r} is wrong")
            os.rename(staging, dest)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return len(entries)


def _check_relative_path(rel: object) -> str:
    """The artifacts contract's path rule: relative, at most 512 bytes, with no
    ``..`` segment, backslash or control character."""
    if (
        not isinstance(rel, str)
        or not rel
        or len(rel.encode("utf-8")) > _MAX_PATH_BYTES
        or rel.startswith("/")
        or "\\" in rel
        or any(ord(c) < 0x20 for c in rel)
        or ".." in rel.split("/")
    ):
        raise ValueError(f"path not allowed in a manifest: {rel!r}")
    return rel


def _regular_files(folder: Path, prefix: str) -> Iterator[tuple[str, Path]]:
    """Every regular file under ``folder`` as (manifest path, file path)."""
    with os.scandir(folder) as listing:
        for item in listing:
            rel = _check_relative_path(prefix + item.name)
            if item.is_symlink():
                raise ValueError(f"{item.path} is a link")
            if item.is_dir(follow_symlinks=False):
                yield from _regular_files(Path(item.path), rel + "/")
            elif item.is_file(follow_symlinks=False):
                yield rel, Path(item.path)
            else:
                raise ValueError(f"{item.path} is not a regular file")


def _manifest_entries(manifest: Any) -> list[dict[str, Any]]:
    """The entries of a fetched ``manifest/v0``, shape-checked fail-closed."""
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"kind", "entries"}
        or manifest["kind"] != "manifest/v0"
        or not isinstance(manifest["entries"], list)
        or len(manifest["entries"]) > _MAX_MANIFEST_ENTRIES
    ):
        raise ValueError("not a manifest/v0")
    entries: list[dict[str, Any]] = manifest["entries"]
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "address", "size"}
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise ValueError(f"malformed manifest entry: {entry!r}")
        validate_address(entry["address"])
    return entries


def _entry_target(root: Path, rel: object) -> Path:
    """Where a manifest entry lands under ``root``: the contract's path rule,
    then a containment check on the joined path, as defense in depth."""
    parts = _check_relative_path(rel).split("/")
    base = os.path.abspath(root)
    target = os.path.normpath(os.path.join(base, *parts))
    if target == base or os.path.commonpath([base, target]) != base:
        raise ValueError(f"manifest path leaves the folder: {rel!r}")
    return Path(target)
