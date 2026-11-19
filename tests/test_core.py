"""Tests for the TFTP packet codec.

These tests exercise the wire format directly: they build the expected byte
strings by hand and compare them against ``encode``, and they decode known
byte strings and compare against the expected packet objects.  Round-trips
are covered for every packet type.
"""

import unittest

from tftp_packet_kit import (
    AckPacket,
    DataPacket,
    ErrorPacket,
    ReadRequestPacket,
    WriteRequestPacket,
    decode,
    encode,
)


class TestReadRequest(unittest.TestCase):
    def test_encode_octet(self):
        pkt = ReadRequestPacket("file.txt", "octet")
        self.assertEqual(encode(pkt), b"\x00\x01file.txt\x00octet\x00")

    def test_encode_defaults_to_octet(self):
        pkt = ReadRequestPacket("file.txt")
        self.assertEqual(encode(pkt), b"\x00\x01file.txt\x00octet\x00")

    def test_mode_is_normalised_to_lowercase(self):
        pkt = ReadRequestPacket("file.txt", "OCTET")
        self.assertEqual(pkt.mode, "octet")
        self.assertEqual(encode(pkt), b"\x00\x01file.txt\x00octet\x00")

    def test_decode(self):
        pkt = decode(b"\x00\x01file.txt\x00octet\x00")
        self.assertEqual(pkt, ReadRequestPacket("file.txt", "octet"))

    def test_decode_uppercase_mode_normalises(self):
        pkt = decode(b"\x00\x01file.txt\x00OCTET\x00")
        self.assertIsInstance(pkt, ReadRequestPacket)
        self.assertEqual(pkt.mode, "octet")

    def test_decode_empty_filename_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x01\x00octet\x00")

    def test_decode_missing_mode_terminator_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x01file.txt\x00octet")

    def test_decode_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x01file.txt\x00octet\x00extra")


class TestWriteRequest(unittest.TestCase):
    def test_encode(self):
        pkt = WriteRequestPacket("out.bin", "netascii")
        self.assertEqual(encode(pkt), b"\x00\x02out.bin\x00netascii\x00")

    def test_decode(self):
        pkt = decode(b"\x00\x02out.bin\x00netascii\x00")
        self.assertEqual(pkt, WriteRequestPacket("out.bin", "netascii"))

    def test_empty_filename_rejected(self):
        with self.assertRaises(ValueError):
            WriteRequestPacket("")


class TestData(unittest.TestCase):
    def test_encode(self):
        pkt = DataPacket(1, b"hello")
        self.assertEqual(encode(pkt), b"\x00\x03\x00\x01hello")

    def test_encode_empty_payload(self):
        pkt = DataPacket(0)
        self.assertEqual(encode(pkt), b"\x00\x03\x00\x00")

    def test_decode(self):
        pkt = decode(b"\x00\x03\x00\x02world")
        self.assertEqual(pkt, DataPacket(2, b"world"))

    def test_decode_empty_payload(self):
        pkt = decode(b"\x00\x03\x00\x00")
        self.assertEqual(pkt, DataPacket(0, b""))

    def test_block_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            DataPacket(0x10000, b"")
        with self.assertRaises(ValueError):
            DataPacket(-1, b"")

    def test_decode_too_short_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x03\x00")


class TestAck(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(encode(AckPacket(0)), b"\x00\x04\x00\x00")
        self.assertEqual(encode(AckPacket(0xFFFF)), b"\x00\x04\xff\xff")

    def test_decode(self):
        self.assertEqual(decode(b"\x00\x04\x00\x07"), AckPacket(7))

    def test_decode_wrong_length_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x04\x00\x07\x00")


class TestError(unittest.TestCase):
    def test_encode(self):
        pkt = ErrorPacket(1, "not found")
        self.assertEqual(encode(pkt), b"\x00\x05\x00\x01not found\x00")

    def test_decode(self):
        pkt = decode(b"\x00\x05\x00\x01not found\x00")
        self.assertEqual(pkt, ErrorPacket(1, "not found"))

    def test_empty_message_allowed(self):
        pkt = ErrorPacket(0, "")
        self.assertEqual(encode(pkt), b"\x00\x05\x00\x00\x00")
        self.assertEqual(decode(b"\x00\x05\x00\x00\x00"), pkt)

    def test_nul_in_message_rejected(self):
        with self.assertRaises(ValueError):
            ErrorPacket(1, "bad\x00msg")

    def test_decode_missing_terminator_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x05\x00\x01not found")

    def test_decode_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x05\x00\x01msg\x00extra")


class TestMalformed(unittest.TestCase):
    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"")

    def test_single_byte_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00")

    def test_unknown_opcode_rejected(self):
        with self.assertRaises(ValueError):
            decode(b"\x00\x06\x00\x00")

    def test_non_bytes_rejected(self):
        with self.assertRaises(TypeError):
            decode("not bytes")  # type: ignore[arg-type]


class TestRoundTrip(unittest.TestCase):
    def test_all_packet_types(self):
        packets = [
            ReadRequestPacket("a.txt", "octet"),
            WriteRequestPacket("b.txt", "netascii"),
            DataPacket(0, b""),
            DataPacket(42, b"payload"),
            AckPacket(0),
            AckPacket(0xFFFF),
            ErrorPacket(2, "access violation"),
            ErrorPacket(0, ""),
        ]
        for pkt in packets:
            with self.subTest(pkt=pkt):
                self.assertEqual(decode(encode(pkt)), pkt)

    def test_data_with_binary_payload(self):
        payload = bytes(range(256))
        pkt = DataPacket(7, payload)
        self.assertEqual(decode(encode(pkt)), pkt)


if __name__ == "__main__":
    unittest.main()
