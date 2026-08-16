"""TCP sequence番号に基づくpayloadの重複除去と整列。"""
from __future__ import annotations

import time
from typing import Dict, Optional


class TcpPayloadOrderer:
    def __init__(self, *, gap_timeout: float = 0.5, max_pending: int = 128):
        self.next_seq: Optional[int] = None
        self.pending: Dict[int, bytes] = {}
        self.gap_since: Optional[float] = None
        self.gap_timeout = float(gap_timeout)
        self.max_pending = int(max_pending)

    def feed(self, seq: int, payload: bytes, now: Optional[float] = None) -> bytes:
        if not payload:
            return b""
        now = time.monotonic() if now is None else float(now)
        seq = int(seq)
        if self.next_seq is None:
            self.next_seq = seq
        if seq < self.next_seq:
            overlap = self.next_seq - seq
            if overlap >= len(payload):
                return b""
            payload, seq = payload[overlap:], self.next_seq
        if seq > self.next_seq:
            previous = self.pending.get(seq)
            if previous is None or len(payload) > len(previous):
                self.pending[seq] = payload
            if self.gap_since is None:
                self.gap_since = now
            if len(self.pending) < self.max_pending and now - self.gap_since < self.gap_timeout:
                return b""
            self.next_seq = min(self.pending)
        chunks = []
        if seq == self.next_seq:
            chunks.append(payload)
            self.next_seq += len(payload)
        while self.next_seq in self.pending:
            part = self.pending.pop(self.next_seq)
            chunks.append(part)
            self.next_seq += len(part)
        self.gap_since = None if not self.pending else self.gap_since
        return b"".join(chunks)
