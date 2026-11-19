# tftp-packet-kit

Encode and decode TFTP packets (RFC 1350) to and from raw bytes.

```python
from tftp_packet_kit import ReadRequestPacket, DataPacket, decode, encode

raw = encode(ReadRequestPacket("boot.img", "octet"))
# b'\x00\x01boot.img\x00octet\x00'

pkt = decode(b'\x00\x03\x00\x01hello')
assert isinstance(pkt, DataPacket)
assert pkt.block == 1
assert pkt.data == b'hello'
```

## Why this exists

TFTP is small enough that people reimplement its packet parsing inline, and
that is where the bugs live: a missing NUL terminator, a block number read
with the wrong endianness, an ERROR packet whose message swallows the next
field.  This library centralises the wire format behind two functions so the
state machine can focus on the state machine.

The trade-off is strictness.  The decoder rejects trailing bytes, empty
filenames, non-ASCII string fields, and unknown opcodes rather than guessing.
A lenient parser that silently accepts a malformed packet will fail later in
a way that is much harder to debug, so this codec fails at the boundary.

## What is not here

Only RFC 1350 is implemented.  The option-extension packets from RFC 2347
(OACK, and the option fields on RRQ/WRQ) are not part of the API.  If you
need them, they are a separate concern.

## The awkward edge

TFTP block numbers wrap at 65535.  This library stores whatever block number
you give it and does not perform the wrap, because the wrap is a property of
the transfer state machine, not of the packet format.  A ``DataPacket`` or
``AckPacket`` with block 65535 is valid; the next block is your problem.

Mode strings are normalised to lowercase on construction.  RFC 1350 defines
the mode as case-insensitive ASCII, so ``ReadRequestPacket("f", "OCTET")``
and ``ReadRequestPacket("f", "octet")`` produce identical packets.  Decoding
``b'\x00\x01f\x00OCTET\x00'`` therefore yields a packet whose ``mode`` is
``"octet"``.

## API

Exported names: ``Packet``, ``ReadRequestPacket``, ``WriteRequestPacket``,
``DataPacket``, ``AckPacket``, ``ErrorPacket``, ``decode``, ``encode``.

- ``ReadRequestPacket(filename, mode="octet")``
- ``WriteRequestPacket(filename, mode="octet")``
- ``DataPacket(block, data=b"")``
- ``AckPacket(block)``
- ``ErrorPacket(code, message)``
- ``decode(raw: bytes) -> Packet``
- ``encode(packet: Packet) -> bytes``

``decode`` raises ``ValueError`` for malformed input and ``TypeError`` for
non-bytes input.  ``encode`` raises ``TypeError`` for objects that are not
one of the packet classes above.
