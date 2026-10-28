from __future__ import annotations

import re
import socket
import struct
import threading

import pytest

from netwatch import dnsprobe


def _response(qid: int, rcode: int, answers: list[tuple[int, bytes]]) -> bytes:
    question = dnsprobe.build_query("www.example.net", "A", qid)[12:]
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    body = b""
    for rtype, rdata in answers:
        # Name as a compression pointer to the question at offset 12.
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + body


def test_build_query() -> None:
    packet = dnsprobe.build_query("example.com", "AAAA", 0x1234)
    assert packet[:12] == bytes.fromhex("123401000001000000000000")
    assert packet[12:] == b"\x07example\x03com\x00" + struct.pack("!HH", 28, 1)


def test_parse_answers_with_compressed_names() -> None:
    cname_target = b"\x07example\x03net\x00"
    data = _response(
        7,
        0,
        [
            (5, cname_target),
            (1, bytes([198, 51, 100, 7])),
            (28, bytes.fromhex("20010db8000000000000000000000007")),
        ],
    )
    assert dnsprobe.parse_response(data, 7) == (
        "NOERROR",
        ("example.net", "198.51.100.7", "2001:db8::7"),
    )


def test_parse_nxdomain() -> None:
    assert dnsprobe.parse_response(_response(7, 3, []), 7) == ("NXDOMAIN", ())


def test_parse_rejects_other_ids_and_garbage() -> None:
    with pytest.raises(dnsprobe.ProbeError, match="doesn't match"):
        dnsprobe.parse_response(_response(8, 0, []), 7)
    with pytest.raises(dnsprobe.ProbeError, match="malformed"):
        dnsprobe.parse_response(b"\x00\x07\x81", 7)


def test_query_times_out_cleanly() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        with pytest.raises(
            dnsprobe.ProbeError, match=re.escape("no reply from 127.0.0.1 within 0.2 s")
        ):
            dnsprobe.query("127.0.0.1", "example.com", port=port, timeout=0.2)


def test_query_against_a_local_responder() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def answer() -> None:
            data, addr = server.recvfrom(512)
            qid = struct.unpack_from("!H", data)[0]
            server.sendto(_response(qid, 0, [(1, bytes([192, 0, 2, 80]))]), addr)

        t = threading.Thread(target=answer)
        t.start()
        reply = dnsprobe.query("127.0.0.1", "www.example.net", port=port, timeout=2)
        t.join()
    assert (reply.rcode, reply.answers) == ("NOERROR", ("192.0.2.80",))
