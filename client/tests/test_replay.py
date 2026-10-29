"""Request replay is an explicit application choice."""

import select
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from dispatch_client import DispatchClient, frame


class RequestReplay(unittest.TestCase):
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
