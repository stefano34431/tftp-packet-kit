"""Core TFTP packet codec implementation.

Only RFC 1350 packets are supported: RRQ (1), WRQ (2), DATA (3), ACK (4),
and ERROR (5).  The option-extension packets from RFC 2347 are deliberately
not implemented because the brief calls for RFC 1350 only.

The module works on raw ``bytes`` and returns concrete packet objects.  No
third-party dependencies are used and no I/O is performed.
"""

from __future__ import annotations

import struct
from typing import Union

__all__ = [
    "AckPacket",
    "DataPacket",
    "ErrorPacket",
    "Packet",
    "ReadRequestPacket",
    "WriteRequestPacket",
    "decode",
    "encode",
]

# RFC 1350 opcodes.
_OP_RRQ = 1
_OP_WRQ = 2
_OP_DATA = 3
_OP_ACK = 4
_OP_ERROR = 5

# RFC 1350 error codes.
ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TRANSFER_ID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7

# TFTP data payloads are limited to 512 bytes by the protocol.  We do not
# enforce this on encode because a caller may legitimately want to build a
# larger packet for testing or for a non-standard server; but we document it.
_MAX_DATA = 512


class Packet:
    """Base class for all TFTP packets.

    Subclasses are immutable by convention: the attributes are set in
    ``__init__`` and callers are expected to treat them as read-only.  This
    keeps ``encode`` cheap and predictable.
    """

    opcode: int

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self.__dict__ == other.__dict__  # type: ignore[attr-defined]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        args = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"{type(self).__name__}({args})"


class ReadRequestPacket(Packet):
    """A read request (RRQ).

    ``mode`` is stored lowercase.  RFC 1350 defines the mode as a case-
    insensitive ASCII string; normalising here means a decoded packet always
    round-trips to the same bytes regardless of the case the peer used.
    """

    opcode = _OP_RRQ

    def __init__(self, filename: str, mode: str = "octet") -> None:
        if not filename:
            raise ValueError("filename must not be empty")
        if not mode:
            raise ValueError("mode must not be empty")
        self.filename = filename
        self.mode = mode.lower()


class WriteRequestPacket(Packet):
    """A write request (WRQ).  See :class:`ReadRequestPacket` for ``mode``."""

    opcode = _OP_WRQ

    def __init__(self, filename: str, mode: str = "octet") -> None:
        if not filename:
            raise ValueError("filename must not be empty")
        if not mode:
            raise ValueError("mode must not be empty")
        self.filename = filename
        self.mode = mode.lower()


class DataPacket(Packet):
    """A DATA packet carrying a block number and a payload.

    Block numbers wrap at 65535 per RFC 1350; the codec stores the value as
    given and does not perform the wrap itself, because the wrap is a property
    of the transfer state machine, not of the packet format.
    """

    opcode = _OP_DATA

    def __init__(self, block: int, data: bytes = b"") -> None:
        if not 0 <= block <= 0xFFFF:
            raise ValueError("block must fit in an unsigned 16-bit integer")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        self.block = block
        self.data = bytes(data)


class AckPacket(Packet):
    """An acknowledgement (ACK)."""

    opcode = _OP_ACK

    def __init__(self, block: int) -> None:
        if not 0 <= block <= 0xFFFF:
            raise ValueError("block must fit in an unsigned 16-bit integer")
        self.block = block


class ErrorPacket(Packet):
    """An ERROR packet.

    The error message is encoded as ASCII with a NUL terminator.  We reject
    NUL bytes in the message because they would truncate the packet on the
    wire and silently change its meaning.
    """

    opcode = _OP_ERROR

    def __init__(self, code: int, message: str) -> None:
        if not 0 <= code <= 0xFFFF:
            raise ValueError("code must fit in an unsigned 16-bit integer")
        if "\x00" in message:
            raise ValueError("error message must not contain NUL")
        self.code = code
        self.message = message


PacketType = Union[
    ReadRequestPacket,
    WriteRequestPacket,
    DataPacket,
    AckPacket,
    ErrorPacket,
]


def _split_cstring(raw: bytes, start: int) -> tuple[str, int]:
    """Return the NUL-terminated ASCII string at ``start`` and the index
    just past the terminator.

    TFTP filenames and modes are ASCII per RFC 1350.  Decoding as ASCII and
    rejecting non-ASCII keeps the codec honest about the wire format rather
    than silently reinterpreting bytes as UTF-8.
    """
    end = raw.find(b"\x00", start)
    if end == -1:
        raise ValueError("unterminated string in packet")
    try:
        text = raw[start:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII byte in string field") from exc
    return text, end + 1


def decode(raw: bytes) -> PacketType:
    """Decode a TFTP packet from ``raw`` bytes.

    Raises ``ValueError`` for malformed packets.  The decoder is strict: it
    rejects trailing bytes after a well-formed packet so that callers cannot
    accidentally accept a packet that a real TFTP implementation would
    discard.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("raw must be bytes-like")
    raw = bytes(raw)
    if len(raw) < 2:
        raise ValueError("packet too short")
    (opcode,) = struct.unpack_from("!H", raw, 0)

    if opcode == _OP_RRQ or opcode == _OP_WRQ:
        filename, pos = _split_cstring(raw, 2)
        mode, pos = _split_cstring(raw, pos)
        if pos != len(raw):
            raise ValueError("trailing bytes after request packet")
        cls = ReadRequestPacket if opcode == _OP_RRQ else WriteRequestPacket
        return cls(filename, mode)

    if opcode == _OP_DATA:
        if len(raw) < 4:
            raise ValueError("DATA packet too short")
        (block,) = struct.unpack_from("!H", raw, 2)
        return DataPacket(block, raw[4:])

    if opcode == _OP_ACK:
        if len(raw) != 4:
            raise ValueError("ACK packet must be exactly 4 bytes")
        (block,) = struct.unpack_from("!H", raw, 2)
        return AckPacket(block)

    if opcode == _OP_ERROR:
        if len(raw) < 5:
            raise ValueError("ERROR packet too short")
        (code,) = struct.unpack_from("!H", raw, 2)
        message, pos = _split_cstring(raw, 4)
        if pos != len(raw):
            raise ValueError("trailing bytes after error message")
        return ErrorPacket(code, message)

    raise ValueError(f"unknown opcode {opcode}")


def encode(packet: PacketType) -> bytes:
    """Encode a packet object to bytes.

    The inverse of :func:`decode` for every packet type produced by this
    module.  Passing anything else raises ``TypeError``.
    """
    if isinstance(packet, (ReadRequestPacket, WriteRequestPacket)):
        return (
            struct.pack("!H", packet.opcode)
            + packet.filename.encode("ascii")
            + b"\x00"
            + packet.mode.encode("ascii")
            + b"\x00"
        )
    if isinstance(packet, DataPacket):
        return struct.pack("!HH", _OP_DATA, packet.block) + packet.data
    if isinstance(packet, AckPacket):
        return struct.pack("!HH", _OP_ACK, packet.block)
    if isinstance(packet, ErrorPacket):
        return (
            struct.pack("!HH", _OP_ERROR, packet.code)
            + packet.message.encode("ascii")
            + b"\x00"
        )
    raise TypeError(f"cannot encode {type(packet).__name__}")
