"""Bounded RFC 6455 frame decoding, rebuilding and operator decision queue.

Payloads enter memory only when the operator explicitly enables WebSocket
interception for an approved proxy scope.
"""
from __future__ import annotations

import os
import re
import threading
import time
import uuid

MAX_FRAME_PAYLOAD = 64 * 1024
MAX_PENDING_FRAMES = 20
DEFAULT_DECISION_TIMEOUT = 30
_VALID_OPCODES = {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}


def decode_frame(raw: bytes, direction: str) -> tuple[dict, bytes]:
    """Decode exactly one complete frame and return unmasked payload bytes."""
    if direction not in {"client-to-server", "server-to-client"}:
        raise ValueError("Invalid WebSocket frame direction.")
    if not isinstance(raw, bytes) or len(raw) < 2:
        raise ValueError("WebSocket frame is incomplete.")
    first, second = raw[0], raw[1]
    fin, opcode, masked = bool(first & 0x80), first & 0x0F, bool(second & 0x80)
    if first & 0x70 or opcode not in _VALID_OPCODES:
        raise ValueError("Reserved WebSocket bits or opcode are not supported.")
    expected_mask = direction == "client-to-server"
    if masked != expected_mask:
        raise ValueError("WebSocket frame masking does not match its direction.")
    length_code = second & 0x7F
    offset = 2
    if length_code == 126:
        if len(raw) < offset + 2:
            raise ValueError("WebSocket frame header is incomplete.")
        length = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        if length < 126:
            raise ValueError("WebSocket frame length is not canonical.")
    elif length_code == 127:
        if len(raw) < offset + 8:
            raise ValueError("WebSocket frame header is incomplete.")
        encoded = raw[offset:offset + 8]
        if encoded[0] & 0x80:
            raise ValueError("WebSocket frame length has its reserved high bit set.")
        length = int.from_bytes(encoded, "big")
        offset += 8
        if length < 65536:
            raise ValueError("WebSocket frame length is not canonical.")
    else:
        length = length_code
    if length > MAX_FRAME_PAYLOAD:
        raise ValueError("WebSocket frame exceeds the 64 KB inspection limit.")
    mask = b""
    if masked:
        if len(raw) < offset + 4:
            raise ValueError("WebSocket frame mask is incomplete.")
        mask = raw[offset:offset + 4]
        offset += 4
    if len(raw) != offset + length:
        raise ValueError("Input must contain exactly one complete WebSocket frame.")
    if opcode >= 0x8 and (not fin or length > 125 or (opcode == 0x8 and length == 1)):
        raise ValueError("WebSocket control frame violates RFC 6455 limits.")
    payload = raw[offset:]
    if masked:
        payload = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
    metadata = {"fin": fin, "opcode": opcode, "masked": masked, "payloadLength": length}
    return metadata, payload


def encode_frame(metadata: dict, payload: bytes, direction: str) -> bytes:
    """Rebuild a frame, applying the masking rule required for its direction."""
    if direction not in {"client-to-server", "server-to-client"}:
        raise ValueError("Invalid WebSocket frame direction.")
    if not isinstance(metadata, dict) or not isinstance(payload, bytes):
        raise ValueError("Frame metadata and payload have invalid types.")
    fin, opcode = metadata.get("fin"), metadata.get("opcode")
    if not isinstance(fin, bool) or isinstance(opcode, bool) or opcode not in _VALID_OPCODES:
        raise ValueError("Frame flags or opcode are invalid.")
    length = len(payload)
    if length > MAX_FRAME_PAYLOAD:
        raise ValueError("WebSocket frame exceeds the 64 KB inspection limit.")
    if opcode >= 0x8 and (not fin or length > 125 or (opcode == 0x8 and length == 1)):
        raise ValueError("WebSocket control frame violates RFC 6455 limits.")
    first = (0x80 if fin else 0) | opcode
    if length < 126:
        header = bytes((first, length))
    elif length <= 0xFFFF:
        header = bytes((first, 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((first, 127)) + length.to_bytes(8, "big")
    if direction == "client-to-server":
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
        return bytes((first, header[1] | 0x80)) + header[2:] + mask + masked
    return header + payload


MAX_MESSAGE_PAYLOAD = 64 * 1024
MAX_MESSAGE_FRAMES = 128
MAX_FRAGMENT_ASSEMBLY_SECONDS = 15


class WebSocketMessageAssembler:
    """Reassemble bounded fragmented messages; pass control frames promptly."""

    def __init__(self):
        self._frames = []
        self._payload = bytearray()
        self._opcode = None
        self._started = None

    @property
    def pending(self):
        return self._opcode is not None

    @property
    def expired(self):
        return self.pending and self._started is not None and (
            time.monotonic() - self._started > MAX_FRAGMENT_ASSEMBLY_SECONDS)

    def feed(self, metadata, payload):
        if not isinstance(metadata, dict) or not isinstance(payload, bytes):
            raise ValueError("WebSocket message fragment is invalid.")
        opcode, fin = metadata.get("opcode"), metadata.get("fin")
        if not isinstance(fin, bool) or opcode not in _VALID_OPCODES:
            raise ValueError("WebSocket frame metadata is invalid.")
        frame = {"metadata": dict(metadata), "payload": payload}
        if opcode >= 0x8:
            return "control", [frame]
        if self._started is not None and time.monotonic() - self._started > MAX_FRAGMENT_ASSEMBLY_SECONDS:
            self.reset()
            raise ValueError("Fragmented WebSocket message exceeded its assembly time limit.")
        if opcode in {0x1, 0x2}:
            if self.pending:
                self.reset()
                raise ValueError("A new WebSocket data message started before the previous one completed.")
            if fin:
                if len(payload) > MAX_MESSAGE_PAYLOAD:
                    raise ValueError("WebSocket message exceeds the 64 KB inspection limit.")
                if opcode == 0x1:
                    payload.decode("utf-8")
                return "complete", [{"metadata": {"fin": True, "opcode": opcode},
                                     "payload": payload, "originalFrames": [frame]}]
            self._opcode = opcode
            self._started = time.monotonic()
            self._frames = [frame]
            self._payload = bytearray(payload)
        elif opcode == 0x0:
            if not self.pending:
                raise ValueError("WebSocket continuation frame has no active message.")
            self._frames.append(frame)
            self._payload.extend(payload)
        else:
            raise ValueError("Unsupported WebSocket data opcode.")
        if len(self._frames) > MAX_MESSAGE_FRAMES or len(self._payload) > MAX_MESSAGE_PAYLOAD:
            self.reset()
            raise ValueError("Fragmented WebSocket message exceeds its bounded assembly limits.")
        if not fin:
            return "pending", []
        frames, message_payload, message_opcode = self._frames, bytes(self._payload), self._opcode
        self.reset()
        if message_opcode == 0x1:
            message_payload.decode("utf-8")
        return "complete", [{"metadata": {"fin": True, "opcode": message_opcode},
                             "payload": message_payload, "originalFrames": frames}]

    def reset(self):
        self._frames = []
        self._payload = bytearray()
        self._opcode = None
        self._started = None


def forward_message_frames(message, payload, direction, edited=False):
    """Rebuild approved data; edited messages become one valid data frame."""
    if not isinstance(message, dict) or not isinstance(payload, bytes):
        raise ValueError("WebSocket message is invalid.")
    metadata = message.get("metadata", {})
    if edited:
        return [encode_frame({"fin": True, "opcode": metadata.get("opcode")}, payload, direction)]
    frames = message.get("originalFrames")
    if frames is None:
        return [encode_frame(metadata, payload, direction)]
    return [encode_frame(frame["metadata"], frame["payload"], direction) for frame in frames]


class WebSocketFrameDecisionQueue:
    """Bounded, timeout-safe queue for explicitly approved frame interception."""

    def __init__(self, max_pending: int = MAX_PENDING_FRAMES,
                 timeout: int = DEFAULT_DECISION_TIMEOUT):
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or not 1 <= max_pending <= 100:
            raise ValueError("Pending frame limit must be from 1 to 100.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
            raise ValueError("Frame decision timeout must be from 1 to 120 seconds.")
        self.max_pending = max_pending
        self.timeout = timeout
        self._lock = threading.RLock()
        self._pending = {}

    def pending(self) -> dict:
        with self._lock:
            items = [entry["public"] for entry in self._pending.values()]
        return {"items": items, "count": len(items), "maxPending": self.max_pending}

    def decide(self, frame_id: str, action: str, edited_payload: str | None = None) -> dict:
        if not isinstance(frame_id, str) or not re.fullmatch(r"[a-f0-9]{32}", frame_id):
            raise ValueError("WebSocket frame decision ID is invalid.")
        if action not in {"forward", "forward_edited", "drop"}:
            raise ValueError("Frame decision must be forward, forward_edited or drop.")
        with self._lock:
            entry = self._pending.get(frame_id)
            if entry is None:
                raise ValueError("This frame is no longer pending.")
            decision = {"action": action}
            if action == "forward_edited":
                if not entry["editable"] or not isinstance(edited_payload, str):
                    raise ValueError("Only bounded UTF-8 text frames can be edited.")
                payload = edited_payload.encode("utf-8")
                if len(payload) > MAX_FRAME_PAYLOAD:
                    raise ValueError("Edited WebSocket payload exceeds 64 KB.")
                if entry["metadata"]["opcode"] not in {0x1, 0x2}:
                    raise ValueError("Control and continuation frames cannot be edited independently.")
                decision["payload"] = payload
            elif edited_payload is not None:
                raise ValueError("Edited payload is only accepted with forward_edited.")
            entry["decision"] = decision
            entry["event"].set()
        return {"id": frame_id, "decision": action, "accepted": True}

    def submit(self, direction: str, metadata: dict, payload: bytes) -> dict:
        if direction not in {"client-to-server", "server-to-client"}:
            raise ValueError("Invalid WebSocket frame direction.")
        if not isinstance(payload, bytes) or len(payload) > MAX_FRAME_PAYLOAD:
            raise ValueError("WebSocket frame payload exceeds 64 KB.")
        if not isinstance(metadata, dict):
            raise ValueError("WebSocket frame metadata is invalid.")
        frame_id = uuid.uuid4().hex
        event = threading.Event()
        editable = metadata.get("opcode") == 0x1 and metadata.get("fin") is True
        try:
            preview = payload.decode("utf-8") if editable else ""
            editable = editable and len(payload) <= MAX_FRAME_PAYLOAD
        except UnicodeDecodeError:
            preview, editable = "", False
        public = {
            "id": frame_id, "direction": direction,
            "opcode": metadata.get("opcode"), "fin": metadata.get("fin"),
            "payloadLength": len(payload), "payload": preview if editable else "",
            "payloadOmitted": not editable, "editable": editable,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decisionTimeoutSeconds": self.timeout,
        }
        entry = {"event": event, "decision": None, "public": public,
                 "metadata": dict(metadata), "payload": payload, "editable": editable}
        with self._lock:
            if len(self._pending) >= self.max_pending:
                raise ValueError("WebSocket frame queue is full; decide pending frames first.")
            self._pending[frame_id] = entry
        try:
            if not event.wait(self.timeout):
                return {"action": "timeout"}
            decision = entry["decision"] or {"action": "drop"}
            if decision["action"] == "forward_edited":
                return {"action": "forward", "payload": decision["payload"]}
            return decision
        finally:
            with self._lock:
                self._pending.pop(frame_id, None)

    def drop_all(self) -> None:
        with self._lock:
            for entry in self._pending.values():
                entry["decision"] = {"action": "drop"}
                entry["event"].set()
