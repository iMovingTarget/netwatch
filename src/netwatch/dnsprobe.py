"""A minimal DNS client, enough to check that a resolver answers and that blocking works.

It sends one query over UDP and decodes A, AAAA and CNAME answers, using only the standard
library so the install script can run it on a fresh host.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import time
from dataclasses import dataclass

from netwatch.errors import NetwatchError

QTYPES = {"A": 1, "CNAME": 5, "AAAA": 28}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class ProbeError(NetwatchError):
    """The resolver didn't answer, or answered with something that isn't DNS."""


@dataclass(frozen=True)
class Response:
    rcode: str
    answers: tuple[str, ...]
    elapsed_ms: float


def build_query(name: str, qtype: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # recursion desired, 1 question
    labels = [label.encode("idna") for label in name.rstrip(".").split(".")]
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return header + qname + struct.pack("!HH", QTYPES[qtype], 1)


def parse_response(data: bytes, qid: int) -> tuple[str, tuple[str, ...]]:
    """(rcode name, answers) from a response to query ``qid``."""
    try:
        rid, flags, qdcount, ancount, _, _ = struct.unpack_from("!HHHHHH", data)
        if rid != qid or not flags & 0x8000:
            raise ProbeError("the reply doesn't match the query")
        offset = 12
        for _ in range(qdcount):
            _, offset = _read_name(data, offset)
            offset += 4
        answers = []
        for _ in range(ancount):
            _, offset = _read_name(data, offset)
            rtype, _, _, rdlength = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset : offset + rdlength]
            if rtype == QTYPES["A"] and rdlength == 4:
                answers.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == QTYPES["AAAA"] and rdlength == 16:
                answers.append(str(ipaddress.IPv6Address(rdata)))
            elif rtype == QTYPES["CNAME"]:
                answers.append(_read_name(data, offset)[0])
            offset += rdlength
    except (struct.error, IndexError, ValueError) as exc:
        raise ProbeError(f"malformed reply: {exc}") from exc
    rcode = flags & 0x000F
    return RCODES.get(rcode, f"RCODE{rcode}"), tuple(answers)


def query(
    server: str, name: str, qtype: str = "A", port: int = 53, timeout: float = 3.0
) -> Response:
    qid = secrets.randbelow(0x10000)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    started = time.monotonic()
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_query(name, qtype, qid), (server, port))
            while True:
                data, _ = sock.recvfrom(4096)
                try:
                    rcode, answers = parse_response(data, qid)
                except ProbeError:
                    continue  # a stray or spoofed packet; keep waiting for ours
                break
        except TimeoutError:
            raise ProbeError(f"no reply from {server} within {timeout:g} s") from None
        except OSError as exc:
            raise ProbeError(f"cannot query {server}: {exc.strerror or exc}") from exc
    return Response(rcode, answers, (time.monotonic() - started) * 1000)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """A possibly compressed domain name at ``offset``, and the offset just after it."""
    labels: list[str] = []
    end = None
    for _ in range(128):  # guards against compression loops
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length == 0:
            return ".".join(labels), end if end is not None else offset + 1
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("compression loop")
