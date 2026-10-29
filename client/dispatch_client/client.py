"""The app-side client for the dispatcher's app surface.

Speaks the length-prefixed JSON wire protocol (see :mod:`dispatch_client.frame`)
over either a Unix domain socket or loopback TCP. Standard library only.

Two connection roles:

* A **request/reply** connection carries every synchronous verb (enqueue, ack,
  approve, ...). It is opened lazily, guarded by a lock so one client instance is
  safe to share across threads, and each request uses a fresh envelope id.
* A **subscription** connection is owned entirely by :meth:`completions`. On a
  ``takeover`` frame (a newer subscriber won) or a dropped connection it
  reconnects and resubscribes; the server redelivers the un-acked ``PERSISTING``
  set, so there is no cursor to track. Acks are sent on the request/reply
  connection, never on the subscription connection.
"""

from __future__ import annotations

import itertools
import socket
import threading
from typing import Any, Iterator, Optional, cast

from . import frame


class DispatchError(Exception):
    """An ``error`` reply from the dispatcher, carrying its code and message."""

    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.retryable = retryable


def _parse_address(address: str) -> tuple[int, Any]:
    """Resolve an address string to (family, connect-target).

    ``unix:/path/to/sock`` -> AF_UNIX; ``host:port`` -> AF_INET loopback TCP.
    """
    if address.startswith("unix:"):
        path = address[len("unix:") :]
        if not path:
            raise ValueError("unix address needs a path: 'unix:/path/sock'")
        if not hasattr(socket, "AF_UNIX"):
            raise ValueError("AF_UNIX is not available on this platform")
        return socket.AF_UNIX, path
    host, sep, port = address.rpartition(":")
    if not sep or not host:
        raise ValueError(f"tcp address must be 'host:port', got {address!r}")
    try:
        return socket.AF_INET, (host, int(port))
    except ValueError as e:
        raise ValueError(f"invalid port in address {address!r}") from e


def _connect(address: str, timeout: Optional[float] = None) -> socket.socket:
    """Open a connected socket. ``timeout`` (set BEFORE connect) bounds the connect and
    every subsequent read/write; ``None`` keeps the socket fully blocking."""
    family, target = _parse_address(address)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        if family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(target)
    except OSError:
        sock.close()
        raise
    return sock


class DispatchClient:
    """A connection to the dispatcher's app surface.

    ``address`` is ``"unix:/path/sock"`` or ``"host:port"``. Connections are
    opened lazily on first use. Not every method needs a connection up front, so
    constructing a client never touches the network.

    ``timeout`` bounds the REQUEST/REPLY connection only (connect + each read), so a
    wedged dispatcher surfaces as an ``OSError`` instead of hanging the caller. The
    subscription connection ignores it — a push stream legitimately blocks forever.
    ``None`` (the default) keeps today's fully-blocking behaviour for long-lived clients.
    """

    def __init__(
        self, address: str, *, timeout: Optional[float] = None, retry_requests: bool = True
    ):
        self._address = address
        self._timeout = timeout
        self._retry_requests = retry_requests
        self._req_lock = threading.Lock()
        self._req_sock: Optional[socket.socket] = None
        self._ids = itertools.count(1)

        # completions() subscription state.
        self._sub_stop = threading.Event()
        self._sub_sock: Optional[socket.socket] = None
        self._sub_lock = threading.Lock()

    # --- request/reply plumbing ---

    def _next_id(self) -> str:
        return f"c{next(self._ids)}"

    def _ensure_req_sock(self) -> socket.socket:
        if self._req_sock is None:
            self._req_sock = _connect(self._address, self._timeout)
        return self._req_sock

    def _drop_req_sock(self) -> None:
        if self._req_sock is not None:
            try:
                self._req_sock.close()
            finally:
                self._req_sock = None

    def _request(self, msg_type: str, body: dict[str, Any]) -> frame.Envelope:
        """Send one request on the shared request/reply connection, return the
        reply envelope. Raises :class:`DispatchError` on an ``error`` reply.

        On a transport failure the connection is dropped and the request is
        retried once on a fresh connection (a persistent app-surface connection
        may have been reaped; the app verbs are all idempotent or read-only).
        """
        with self._req_lock:
            attempts = 2 if self._retry_requests else 1
            for attempt in range(1, attempts + 1):
                sock = self._ensure_req_sock()
                req_id = self._next_id()
                try:
                    frame.write_message(sock, req_id, msg_type, body)
                    env = frame.read_message(sock)
                except (OSError, ConnectionError, frame.FrameError):
                    self._drop_req_sock()
                    if attempt == attempts:
                        raise
                    continue
                if env["type"] == "error":
                    err = env["body"]
                    raise DispatchError(
                        err.get("code", "internal"),
                        err.get("message", ""),
                        bool(err.get("retryable", False)),
                    )
                return env
            raise AssertionError("unreachable")

    # --- app verbs ---

    def job(self, job_id: str) -> dict[str, Any]:
        """Read one job without paging the fleet's entire history."""
        return self._request("job", {"job_id": job_id})["body"]

    def wait(self, job_id: str) -> dict[str, Any]:
        """Block until execution ends, independently of the completion subscriber."""
        observer = DispatchClient(self._address, timeout=self._timeout, retry_requests=False)
        try:
            return observer._request("wait", {"job_id": job_id})["body"]
        finally:
            observer.close()

    def enqueue(self, jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enqueue a batch of jobs. Idempotent on a live ``job_key``: a repeat
        returns the existing ``job_id`` with ``created=False``.

        Each job dict: ``{"job_key", "lane", "invocation_address", "policy"?,
        "cost_estimate_usd"?}``. Returns the ``results`` list of
        ``{"job_key", "job_id", "created"}``.
        """
        env = self._request("enqueue", {"jobs": jobs})
        return cast(list[dict[str, Any]], env["body"]["results"])

    def logs(self, job_id: str, after: int = 0, wait: bool = True) -> dict[str, Any]:
        """Read CAS-addressed log chunks without taking over completions."""
        with DispatchClient(self._address, retry_requests=False) as observer:
            return observer._request("logs", {"job_id": job_id, "after": after, "wait": wait})[
                "body"
            ]

    def ack(self, job_id: str, disposition: str, reason: Optional[str] = None) -> None:
        """Drain a job from the PERSISTING inbox. ``disposition`` is
        ``"persisted"`` or ``"rejected"``. Idempotent."""
        body: dict[str, Any] = {"job_id": job_id, "disposition": disposition}
        if reason is not None:
            body["reason"] = reason
        self._request("ack", body)

    def approve(self, job_id: str, author: str, reason: str) -> None:
        """Approve a priced job parked in AWAITING_APPROVAL."""
        self._request("approve", {"job_id": job_id, "author": author, "reason": reason})

    def reject(self, job_id: str, author: str, reason: str) -> None:
        """Reject a priced job; releases its budget reservation."""
        self._request("reject", {"job_id": job_id, "author": author, "reason": reason})

    def cancel(self, job_id: str, reason: str) -> None:
        """Cancel any non-terminal job."""
        self._request("cancel", {"job_id": job_id, "reason": reason})

    def jobs(
        self,
        filter: Optional[dict[str, Any]] = None,
        page: Optional[int] = None,
    ) -> dict[str, Any]:
        """Read the job view. ``filter`` may carry ``state``/``lane``/
        ``job_key_prefix``; ``page`` is an integer offset. Returns
        ``{"jobs": [...], "next_page"?}``."""
        body: dict[str, Any] = {}
        if filter is not None:
            body["filter"] = filter
        if page is not None:
            body["page"] = page
        result = self._request("jobs", body)["body"]
        # An empty result marshals `jobs` as JSON null on the Go side; normalize.
        result["jobs"] = result.get("jobs") or []
        return result

    def fleet(self) -> list[dict[str, Any]]:
        """Return the per-runner fleet snapshot."""
        # An empty fleet marshals `runners` as JSON null on the Go side.
        return cast(list[dict[str, Any]], self._request("fleet", {})["body"]["runners"] or [])

    def budget(self) -> dict[str, Any]:
        """Return the budget snapshot (cap, reserved, spent, ledger)."""
        return self._request("budget", {})["body"]

    def sweep(self) -> dict[str, Any]:
        """Run the timer pass on demand; returns the sweep summary."""
        return self._request("sweep", {})["body"]

    def stats(self, window_s: Optional[int] = None) -> dict[str, Any]:
        """Return the drain-health snapshot: job counts by (lane, state), settled
        attempt outcomes over the trailing window (server default 15m), the grouped
        recent failure reasons, and the oldest-QUEUED age in seconds. Read-only —
        the source for the app's exported drain gauges and the stall alert."""
        body: dict[str, Any] = {}
        if window_s is not None:
            body["window_s"] = window_s
        view = self._request("stats", body)["body"]
        # Empty slices marshal as JSON null on the Go side; normalize.
        for key in ("jobs", "attempts", "recent_failures"):
            view[key] = view.get(key) or []
        return view

    # --- subscription ---

    def completions(self) -> Iterator[dict[str, Any]]:
        """Yield completion bodies as they arrive, forever, until :meth:`close`.

        Opens a dedicated subscription connection, sends ``subscribe``, and
        yields each ``completion`` body dict. On a ``takeover`` frame or a
        dropped connection it reconnects and resubscribes; the server redelivers
        the un-acked PERSISTING set on every (re)subscribe, so no cursor is
        tracked. Ack each yielded job (via :meth:`ack`) to drain it from the
        inbox — acks go on the separate request/reply connection.

        Blocking generator: iterate it on a dedicated thread if you need to do
        other work. Call :meth:`close` (or break out and call it) to stop.
        """
        self._sub_stop.clear()
        while not self._sub_stop.is_set():
            try:
                sock = _connect(self._address)
            except OSError:
                if self._sub_stop.is_set():
                    return
                if not self._retry_requests:
                    raise
                continue
            with self._sub_lock:
                if self._sub_stop.is_set():
                    sock.close()
                    return
                self._sub_sock = sock
            try:
                frame.write_message(sock, "sub", "subscribe", {})
                while True:
                    env = frame.read_message(sock)
                    msg_type = env["type"]
                    if msg_type == "completion":
                        yield env["body"]
                    elif msg_type == "takeover":
                        if not self._retry_requests:
                            raise DispatchError("conflict", "completion subscriber replaced")
                        break  # a newer subscriber won; reconnect and resume
                    elif msg_type == "error":
                        err = env["body"]
                        raise DispatchError(
                            err.get("code", "internal"),
                            err.get("message", ""),
                            bool(err.get("retryable", False)),
                        )
                    # any other frame type is ignored (forward-compat)
            except (OSError, ConnectionError, frame.FrameError):
                if self._sub_stop.is_set():
                    return
                if not self._retry_requests:
                    raise
                # transient drop: fall through to reconnect
            finally:
                with self._sub_lock:
                    if self._sub_sock is sock:
                        self._sub_sock = None
                try:
                    sock.close()
                except OSError:
                    pass

    def stop_completions(self) -> None:
        """Signal :meth:`completions` to stop and close its connection.

        Wakes a blocked read by closing the subscription socket. The generator
        returns cleanly on its next loop iteration.
        """
        self._sub_stop.set()
        with self._sub_lock:
            if self._sub_sock is not None:
                try:
                    self._sub_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._sub_sock.close()
                except OSError:
                    pass
                self._sub_sock = None

    def close(self) -> None:
        """Close all connections and stop the completion stream."""
        self.stop_completions()
        with self._req_lock:
            self._drop_req_sock()

    def __enter__(self) -> "DispatchClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
