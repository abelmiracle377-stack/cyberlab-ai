"""Regression tests for bounded RFC 6455 WebSocket frame handling.

These lock in the safety behaviour the native interception proxy relies on:
canonical length enforcement, masking-direction rules, control-frame limits,
bounded fragment reassembly and faithful frame rebuilding.
"""
import unittest

import websocket_interception as ws

C2S = "client-to-server"
S2C = "server-to-client"


def server_frame(opcode, payload, fin=True):
    """Build an unmasked server-to-client frame with a canonical length field."""
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, length))
    elif length <= 0xFFFF:
        header = bytes((first, 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((first, 127)) + length.to_bytes(8, "big")
    return header + payload


class DecodeFrameTests(unittest.TestCase):
    def test_decodes_unmasked_server_text_frame(self):
        metadata, payload = ws.decode_frame(server_frame(0x1, b"hello"), S2C)
        self.assertEqual(payload, b"hello")
        self.assertEqual(metadata["opcode"], 0x1)
        self.assertTrue(metadata["fin"])
        self.assertFalse(metadata["masked"])

    def test_masked_client_frame_round_trips(self):
        raw = ws.encode_frame({"fin": True, "opcode": 0x2}, b"binary-body", C2S)
        self.assertTrue(raw[1] & 0x80, "client-to-server frames must be masked")
        metadata, payload = ws.decode_frame(raw, C2S)
        self.assertEqual(payload, b"binary-body")
        self.assertTrue(metadata["masked"])

    def test_rejects_reserved_bits(self):
        frame = bytearray(server_frame(0x1, b"x"))
        frame[0] |= 0x40  # set RSV1
        with self.assertRaisesRegex(ValueError, "Reserved"):
            ws.decode_frame(bytes(frame), S2C)

    def test_rejects_unknown_opcode(self):
        with self.assertRaisesRegex(ValueError, "Reserved"):
            ws.decode_frame(server_frame(0x3, b"x"), S2C)

    def test_rejects_masking_direction_mismatch(self):
        # An unmasked frame on the client-to-server channel must be rejected.
        with self.assertRaisesRegex(ValueError, "masking"):
            ws.decode_frame(server_frame(0x1, b"x"), C2S)
        # And a masked frame on the server-to-client channel.
        masked = ws.encode_frame({"fin": True, "opcode": 0x1}, b"x", C2S)
        with self.assertRaisesRegex(ValueError, "masking"):
            ws.decode_frame(masked, S2C)

    def test_rejects_non_canonical_two_byte_length(self):
        # length 10 encoded with the 126 extended form is non-canonical.
        frame = bytes((0x81, 126)) + (10).to_bytes(2, "big") + b"x" * 10
        with self.assertRaisesRegex(ValueError, "canonical"):
            ws.decode_frame(frame, S2C)

    def test_rejects_non_canonical_eight_byte_length(self):
        frame = bytes((0x81, 127)) + (100).to_bytes(8, "big") + b"x" * 100
        with self.assertRaisesRegex(ValueError, "canonical"):
            ws.decode_frame(frame, S2C)

    def test_rejects_eight_byte_length_reserved_high_bit(self):
        frame = bytes((0x81, 127)) + bytes([0x80, 0, 0, 0, 0, 1, 0, 0])
        with self.assertRaisesRegex(ValueError, "reserved high bit"):
            ws.decode_frame(frame, S2C)

    def test_rejects_payload_over_inspection_limit(self):
        oversize = ws.MAX_FRAME_PAYLOAD + 1
        frame = bytes((0x82, 127)) + oversize.to_bytes(8, "big") + b"x" * 10
        with self.assertRaisesRegex(ValueError, "64 KB inspection limit"):
            ws.decode_frame(frame, S2C)

    def test_requires_exactly_one_complete_frame(self):
        two = server_frame(0x1, b"a") + server_frame(0x1, b"b")
        with self.assertRaisesRegex(ValueError, "exactly one complete"):
            ws.decode_frame(two, S2C)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            ws.decode_frame(server_frame(0x1, b"ab")[:1], S2C)

    def test_rejects_oversized_or_fragmented_control_frame(self):
        with self.assertRaisesRegex(ValueError, "control frame"):
            ws.decode_frame(server_frame(0x9, b"x" * 126), S2C)  # ping > 125
        with self.assertRaisesRegex(ValueError, "control frame"):
            ws.decode_frame(server_frame(0x8, b"x", fin=False), S2C)  # non-final close

    def test_rejects_close_frame_with_single_byte(self):
        with self.assertRaisesRegex(ValueError, "control frame"):
            ws.decode_frame(server_frame(0x8, b"x"), S2C)


class EncodeFrameTests(unittest.TestCase):
    def test_server_frames_are_not_masked(self):
        raw = ws.encode_frame({"fin": True, "opcode": 0x1}, b"data", S2C)
        self.assertFalse(raw[1] & 0x80)
        metadata, payload = ws.decode_frame(raw, S2C)
        self.assertEqual(payload, b"data")

    def test_round_trips_each_length_class(self):
        for size in (5, 126, 0xFFFF, ws.MAX_FRAME_PAYLOAD):
            with self.subTest(size=size):
                body = b"z" * size
                raw = ws.encode_frame({"fin": True, "opcode": 0x2}, body, S2C)
                _, payload = ws.decode_frame(raw, S2C)
                self.assertEqual(payload, body)

    def test_rejects_boolean_or_unknown_opcode(self):
        with self.assertRaisesRegex(ValueError, "opcode"):
            ws.encode_frame({"fin": True, "opcode": True}, b"x", S2C)
        with self.assertRaisesRegex(ValueError, "opcode"):
            ws.encode_frame({"fin": True, "opcode": 0x5}, b"x", S2C)

    def test_rejects_control_frame_violations(self):
        with self.assertRaisesRegex(ValueError, "control frame"):
            ws.encode_frame({"fin": True, "opcode": 0x9}, b"x" * 126, S2C)
        with self.assertRaisesRegex(ValueError, "control frame"):
            ws.encode_frame({"fin": False, "opcode": 0x8}, b"ok", S2C)


class MessageAssemblerTests(unittest.TestCase):
    def setUp(self):
        self.assembler = ws.WebSocketMessageAssembler()

    def test_single_text_message_completes_immediately(self):
        status, messages = self.assembler.feed({"fin": True, "opcode": 0x1}, b"hi")
        self.assertEqual(status, "complete")
        self.assertEqual(messages[0]["payload"], b"hi")
        self.assertFalse(self.assembler.pending)

    def test_fragmented_message_reassembles_in_order(self):
        self.assertEqual(self.assembler.feed({"fin": False, "opcode": 0x2}, b"foo")[0], "pending")
        self.assertEqual(self.assembler.feed({"fin": False, "opcode": 0x0}, b"bar")[0], "pending")
        status, messages = self.assembler.feed({"fin": True, "opcode": 0x0}, b"baz")
        self.assertEqual(status, "complete")
        self.assertEqual(messages[0]["payload"], b"foobarbaz")
        self.assertEqual(len(messages[0]["originalFrames"]), 3)

    def test_control_frame_passes_through_during_assembly(self):
        self.assembler.feed({"fin": False, "opcode": 0x1}, b"part")
        status, messages = self.assembler.feed({"fin": True, "opcode": 0x9}, b"ping")
        self.assertEqual(status, "control")
        self.assertEqual(messages[0]["payload"], b"ping")
        self.assertTrue(self.assembler.pending)  # the text message is still open

    def test_continuation_without_active_message_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no active message"):
            self.assembler.feed({"fin": True, "opcode": 0x0}, b"orphan")

    def test_new_data_message_before_completion_is_rejected(self):
        self.assembler.feed({"fin": False, "opcode": 0x1}, b"part")
        with self.assertRaisesRegex(ValueError, "before the previous one completed"):
            self.assembler.feed({"fin": True, "opcode": 0x1}, b"new")

    def test_invalid_utf8_text_message_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            self.assembler.feed({"fin": True, "opcode": 0x1}, b"\xff\xfe")

    def test_too_many_fragments_are_rejected(self):
        self.assembler.feed({"fin": False, "opcode": 0x2}, b"x")
        with self.assertRaisesRegex(ValueError, "bounded assembly limits"):
            for _ in range(ws.MAX_MESSAGE_FRAMES + 2):
                self.assembler.feed({"fin": False, "opcode": 0x0}, b"x")


class ForwardMessageFramesTests(unittest.TestCase):
    def test_edited_message_becomes_single_masked_data_frame(self):
        message = {"metadata": {"fin": True, "opcode": 0x1}}
        frames = ws.forward_message_frames(message, b"edited", C2S, edited=True)
        self.assertEqual(len(frames), 1)
        metadata, payload = ws.decode_frame(frames[0], C2S)
        self.assertEqual(payload, b"edited")
        self.assertTrue(metadata["masked"])

    def test_unedited_message_replays_original_frames(self):
        message = {
            "metadata": {"fin": True, "opcode": 0x2},
            "originalFrames": [
                {"metadata": {"fin": False, "opcode": 0x2}, "payload": b"foo"},
                {"metadata": {"fin": True, "opcode": 0x0}, "payload": b"bar"},
            ],
        }
        frames = ws.forward_message_frames(message, b"foobar", S2C)
        self.assertEqual(len(frames), 2)
        self.assertEqual(ws.decode_frame(frames[0], S2C)[1], b"foo")
        self.assertEqual(ws.decode_frame(frames[1], S2C)[1], b"bar")


if __name__ == "__main__":
    unittest.main()
