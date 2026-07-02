"""dispatch-client — a pure-stdlib Python client for the dispatcher app surface.

Speaks the length-prefixed JSON wire protocol to the Go dispatcher over a Unix
domain socket or loopback TCP.

    from dispatch_client import DispatchClient

    client = DispatchClient("unix:/run/dispatch.sock")  # or "127.0.0.1:7701"
    client.enqueue([{"job_key": "k1", "lane": "embed",
                     "invocation_address": "sha256:" + "0" * 64}])
    for completion in client.completions():
        client.ack(completion["job_id"], "persisted")
"""

from .client import DispatchClient, DispatchError
from .frame import CONTRACT_VERSION, FrameError

__all__ = ["DispatchClient", "DispatchError", "FrameError", "CONTRACT_VERSION"]

# The CAS client (dispatch_client.cas) is imported explicitly by consumers that
# need it — it carries the one non-stdlib dependency (PyNaCl for PoP signing):
#     from dispatch_client.cas import CasClient, Credential
