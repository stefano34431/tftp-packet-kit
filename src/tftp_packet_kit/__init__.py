"""TFTP packet codec.

This package provides encoding and decoding of TFTP packets as defined in
RFC 1350.  The public API is intentionally small: ``decode`` and ``encode``
operate on ``bytes`` and ``Packet`` instances, and a handful of packet
classes are exported for construction and inspection.
"""

from .core import (
    AckPacket,
    DataPacket,
    ErrorPacket,
    Packet,
    ReadRequestPacket,
    WriteRequestPacket,
    decode,
    encode,
)

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
