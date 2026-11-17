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

    def feed(self, data: bytes) -> None:
        if self.disabled or not data:
            return
        self._buffer.extend(data)
        if len(self._buffer) > MAX_OBSERVED_FRAME + MAX_HEADER_BUFFER:
            self.disabled = True
            self._buffer.clear()
            return
        while not self.disabled:
            if self._current is not None:
                take = min(self._payload_remaining, len(self._buffer))
                if take:
                    del self._buffer[:take]
                    self._payload_remaining -= take
                if self._payload_remaining == 0:
                    self._emit()
                    continue
                return
            parsed = self._parse_header()
            if parsed is None:
                return
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
        cursor = 2
        if length_code == 126:
            if len(self._buffer) < cursor + 2:
                return None
            length = int.from_bytes(self._buffer[cursor:cursor + 2], "big")
            cursor += 2
        elif length_code == 127:
            if len(self._buffer) < cursor + 8:
                return None
            raw_length = bytes(self._buffer[cursor:cursor + 8])
            if raw_length[0] & 0x80:
                self.disabled = True
                return None
            length = int.from_bytes(raw_length, "big")
            cursor += 8
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
        if opcode >= 0x8 and (not fin or length > 125):
            self.disabled = True
            self._buffer.clear()
            return None
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
