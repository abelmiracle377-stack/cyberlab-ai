"""Regression tests for the payload-free WebSocket frame metadata observer.

The observer sits beside the opaque relay and must parse frame boundaries
across arbitrary byte splits, track fragmentation, and fail closed (disable
itself) on any protocol violation without ever retaining payload bytes.
"""
import unittest

from websocket_frames import WebSocketFrameObserver

S2C = "server-to-client"
C2S = "client-to-server"


def server_frame(opcode, payload, fin=True):
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, length))
    elif length <= 0xFFFF:
        header = bytes((first, 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((first, 127)) + length.to_bytes(8, "big")
    return header + payload


def collect(direction, *chunks, byte_by_byte=False):
    seen = []
    observer = WebSocketFrameObserver(direction, seen.append)
    for chunk in chunks:
        if byte_by_byte:
            for value in chunk:
                observer.feed(bytes([value]))
        else:
            observer.feed(chunk)
    return observer, seen


class FrameBoundaryTests(unittest.TestCase):
    def test_emits_one_record_per_frame(self):
        _, seen = collect(S2C, server_frame(0x1, b"hello"))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["opcode"], 0x1)
        self.assertEqual(seen[0]["opcodeName"], "text")
        self.assertEqual(seen[0]["payloadLength"], 5)
        self.assertTrue(seen[0]["messageComplete"])

    def test_records_carry_no_payload_bytes(self):
        _, seen = collect(S2C, server_frame(0x2, b"secret-body"))
        self.assertNotIn("payload", seen[0])
        self.assertEqual(seen[0]["payloadLength"], len(b"secret-body"))

    def test_parses_identically_when_fed_one_byte_at_a_time(self):
        stream = server_frame(0x1, b"abc") + server_frame(0x2, b"xyzw")
        _, whole = collect(S2C, stream)
        _, split = collect(S2C, stream, byte_by_byte=True)
        self.assertEqual([f["payloadLength"] for f in whole], [3, 4])
        self.assertEqual([f["payloadLength"] for f in split], [3, 4])

    def test_extended_length_frame_is_parsed(self):
        body = b"q" * 200  # uses the 126 extended length form
        _, seen = collect(S2C, server_frame(0x2, body))
        self.assertEqual(seen[0]["payloadLength"], 200)

    def test_tracks_fragmented_message_grouping(self):
        stream = (
            server_frame(0x1, b"aa", fin=False)
            + server_frame(0x0, b"bb", fin=False)
            + server_frame(0x0, b"cc", fin=True)
        )
        _, seen = collect(S2C, stream)
        self.assertEqual([f["fragmentIndex"] for f in seen], [0, 1, 2])
        self.assertEqual({f["messageId"] for f in seen}, {seen[0]["messageId"]})
        self.assertEqual([f["messageComplete"] for f in seen], [False, False, True])

    def test_message_id_increments_per_new_message(self):
        stream = server_frame(0x1, b"a") + server_frame(0x1, b"b")
        _, seen = collect(S2C, stream)
        self.assertEqual(seen[1]["messageId"], seen[0]["messageId"] + 1)


class FailClosedTests(unittest.TestCase):
    def test_reserved_bits_disable_observer(self):
        frame = bytearray(server_frame(0x1, b"x"))
        frame[0] |= 0x40
        observer, seen = collect(S2C, bytes(frame))
        self.assertTrue(observer.disabled)
        self.assertEqual(seen, [])

    def test_masking_direction_mismatch_disables_observer(self):
        # Unmasked frame arriving on the client-to-server channel is invalid.
        observer, seen = collect(C2S, server_frame(0x1, b"x"))
        self.assertTrue(observer.disabled)
        self.assertEqual(seen, [])

    def test_orphan_continuation_disables_observer(self):
        observer, seen = collect(S2C, server_frame(0x0, b"x"))
        self.assertTrue(observer.disabled)
        self.assertEqual(seen, [])

    def test_new_data_message_during_fragmentation_disables_observer(self):
        stream = server_frame(0x1, b"a", fin=False) + server_frame(0x1, b"b")
        observer, seen = collect(S2C, stream)
        self.assertTrue(observer.disabled)
        self.assertEqual(len(seen), 1)  # only the first fragment was emitted

    def test_oversized_control_frame_disables_observer(self):
        observer, seen = collect(S2C, server_frame(0x9, b"x" * 126))
        self.assertTrue(observer.disabled)
        self.assertEqual(seen, [])

    def test_unparseable_header_run_disables_after_buffer_limit(self):
        # A stream of 0x00 bytes never completes a valid header (opcode 0 with
        # no active message) and must disable rather than buffer unboundedly.
        observer, seen = collect(S2C, b"\x00" * 64)
        self.assertTrue(observer.disabled)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
