"""Bounded, payload-free RFC 6455 frame metadata observer.

This parser is deliberately observational: it never changes or stores frame
payloads. It is used alongside the opaque WebSocket relay.
"""
from __future__ import annotations

import time

MAX_OBSERVED_FRAME = 1024 * 1024
MAX_HEADER_BUFFER = 14
OPCODES = {
    0x0: "continuation", 0x1: "text", 0x2: "binary",
    0x8: "close", 0x9: "ping", 0xA: "pong",
}


class WebSocketFrameObserver:
    """Incrementally parse frame boundaries without retaining payload bytes."""

    def __init__(self, direction: str, on_frame):
        if direction not in {"client-to-server", "server-to-client"}:
            raise ValueError("Invalid WebSocket frame direction.")
        self.direction = direction
        self.on_frame = on_frame
        self._buffer = bytearray()
        self._payload_remaining = 0
        self._current = None
        self.disabled = False
        self._fragmented_message = False

    def feed(self, data: bytes) -> None:
        if self.disabled or not data:
            return
        view = memoryview(data)
        offset = 0
        while offset < len(view) and not self.disabled:
            if self._current is not None:
                take = min(self._payload_remaining, len(view) - offset)
                offset += take
                self._payload_remaining -= take
                if self._payload_remaining == 0:
                    self._emit()
                continue

            # Buffer only enough bytes to parse one maximum-sized frame header.
            room = MAX_HEADER_BUFFER - len(self._buffer)
            if room <= 0:
                self.disabled = True
                self._buffer.clear()
                return
            take = min(room, len(view) - offset)
            self._buffer.extend(view[offset:offset + take])
            offset += take
            parsed = self._parse_header()
            if parsed is None:
                if len(self._buffer) >= MAX_HEADER_BUFFER:
                    self.disabled = True
                    self._buffer.clear()
                continue
            consumed, metadata = parsed
            del self._buffer[:consumed]
            self._current = metadata
            self._payload_remaining = metadata["payloadLength"]
            if self._payload_remaining == 0:
                self._emit()

    def _parse_header(self):
        if len(self._buffer) < 2:
            return None
        first, second = self._buffer[0], self._buffer[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length_code = second & 0x7F
        # This observer supports no negotiated extensions, so RSV bits must be zero.
        if first & 0x70 or opcode not in {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}:
            self.disabled = True
            self._buffer.clear()
            return None
        cursor = 2
        if length_code == 126:
            if len(self._buffer) < cursor + 2:
                return None
            length = int.from_bytes(self._buffer[cursor:cursor + 2], "big")
            cursor += 2
            if length < 126:
                self.disabled = True
                self._buffer.clear()
                return None
        elif length_code == 127:
            if len(self._buffer) < cursor + 8:
                return None
            raw_length = bytes(self._buffer[cursor:cursor + 8])
            if raw_length[0] & 0x80:
                self.disabled = True
                return None
            length = int.from_bytes(raw_length, "big")
            cursor += 8
            if length < 65536:
                self.disabled = True
                self._buffer.clear()
                return None
        else:
            length = length_code
        if masked:
            cursor += 4
        if len(self._buffer) < cursor:
            return None
        expected_mask = self.direction == "client-to-server"
        if masked != expected_mask or length > MAX_OBSERVED_FRAME:
            self.disabled = True
            self._buffer.clear()
            return None
        if opcode >= 0x8 and (not fin or length > 125 or (opcode == 0x8 and length == 1)):
            self.disabled = True
            self._buffer.clear()
            return None
        if opcode == 0x0:
            if not self._fragmented_message:
                self.disabled = True
                self._buffer.clear()
                return None
            if fin:
                self._fragmented_message = False
        elif opcode in {0x1, 0x2}:
            if self._fragmented_message:
                self.disabled = True
                self._buffer.clear()
                return None
            if not fin:
                self._fragmented_message = True
        return cursor, {
            "direction": self.direction, "fin": fin, "opcode": opcode,
            "opcodeName": OPCODES.get(opcode, "reserved"),
            "masked": masked, "payloadLength": length,
        }

    def _emit(self):
        item = self._current
        self._current = None
        self._payload_remaining = 0
        if item is not None:
            item["capturedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.on_frame(item)
