"""保存ストリーム／TCP断片からアプリケーションメッセージを復元する。"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import List, Optional


MAX_RECORD_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class ApplicationMessage:
    opcode: int
    payload: bytes
    outer_type: int
    sequence: Optional[int] = None
    command: Optional[int] = None
    protobuf: bytes = b""


def _decompress_zstd(data: bytes) -> bytes:
    import zstandard as zstd

    with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
        return reader.read(MAX_RECORD_SIZE)


def _decode_snapshot_record(body: bytes) -> Optional[ApplicationMessage]:
    """0x8002のメタデータを除き、Zstd展開済みProtobufを返す。"""
    magic = body.find(b"\x28\xb5\x2f\xfd")
    if magic < 0:
        return None
    try:
        protobuf = _decompress_zstd(body[magic:])
    except Exception:
        return None
    if not protobuf:
        return None
    return ApplicationMessage(0x8002, body, 0x8002, protobuf=protobuf)


def split_application_messages(data: bytes, outer_type: int) -> List[ApplicationMessage]:
    """外側payloadに連結された内側メッセージを分離する。"""
    result: List[ApplicationMessage] = []
    offset = 0
    while offset + 6 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], "big")
        if size < 6 or size > MAX_RECORD_SIZE or offset + size > len(data):
            break
        opcode = int.from_bytes(data[offset + 4:offset + 6], "big")
        payload = data[offset + 6:offset + size]
        sequence = command = None
        protobuf = b""
        # opcode 2の通知は16-byte envelope + 1-byte command + protobuf。
        if opcode == 2 and len(payload) >= 17 and payload[4:10] == b"c3SB\x00\x00":
            sequence = int.from_bytes(payload[10:14], "big")
            command = payload[15]
            protobuf = payload[16:]
        result.append(ApplicationMessage(opcode, payload, outer_type, sequence, command, protobuf))
        offset += size
    return result


class StreamDecoder:
    """任意のTCP分割を受け取り、完成した外側レコードだけを返す。"""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def _find_record_start(self) -> int:
        """既知のサーバーレコード境界を探索する。TCP途中開始時の誤待機を防ぐ。"""
        limit = max(0, len(self._buffer) - 9)
        for offset in range(limit + 1):
            size = int.from_bytes(self._buffer[offset:offset + 4], "big")
            if not (10 <= size <= MAX_RECORD_SIZE) or offset + size > len(self._buffer):
                continue
            outer_type = int.from_bytes(self._buffer[offset + 4:offset + 6], "big")
            if outer_type in (4, 6, 7, 0x8002, 0x8006):
                return offset
        return -1

    def feed(self, chunk: bytes) -> List[ApplicationMessage]:
        self._buffer.extend(chunk)
        messages: List[ApplicationMessage] = []
        while len(self._buffer) >= 4:
            size = int.from_bytes(self._buffer[:4], "big")
            header_type = int.from_bytes(self._buffer[4:6], "big") if len(self._buffer) >= 6 else -1
            if size < 4 or size > MAX_RECORD_SIZE or header_type not in (4, 6, 7, 0x8002, 0x8006):
                start = self._find_record_start()
                if start > 0:
                    del self._buffer[:start]
                elif start < 0:
                    # 境界候補用の末尾だけを残す。
                    if len(self._buffer) > 9:
                        del self._buffer[:-9]
                    else:
                        # 4～9 byteの不完全／未知ヘッダーは次のTCP断片を待つ。
                        # 削除できない状態でcontinueすると無限ループになる。
                        break
                continue
            if len(self._buffer) < size:
                break
            body = bytes(self._buffer[4:size])
            del self._buffer[:size]
            if len(body) < 6:
                continue
            outer_type = int.from_bytes(body[:2], "big")
            payload = body[6:]
            if outer_type == 0x8002:
                message = _decode_snapshot_record(payload)
                if message is not None:
                    messages.append(message)
                continue
            if outer_type == 0x8006:
                try:
                    payload = _decompress_zstd(payload)
                except Exception:
                    continue
            if outer_type in (6, 0x8006):
                messages.extend(split_application_messages(payload, outer_type))
        return messages