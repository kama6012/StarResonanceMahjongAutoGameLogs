"""復元した卓スナップショットを対局単位のJSON牌譜へ保存する。"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from protocol import TableSnapshot


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


def snapshot_to_record(snapshot: TableSnapshot, *, captured_at: Optional[str] = None) -> Dict[str, Any]:
    """TableSnapshotを外部ツールでも扱いやすいJSON互換辞書へ変換する。"""
    players = []
    for index in range(4):
        players.append({
            "index": index,
            "score": snapshot.scores[index],
            "seat_wind": snapshot.seat_winds[index],
            "riichi_state": snapshot.riichi_states[index],
            "card_count": snapshot.card_counts[index],
            "last_draw": snapshot.last_draw_flags[index],
            "discards": list(snapshot.discards[index]),
            "melds": [list(meld) for meld in snapshot.player_melds[index]],
            "meld_types": list(snapshot.player_meld_types[index]),
            "meld_called_tiles": list(snapshot.meld_called_tiles[index]),
            "meld_from_players": list(snapshot.meld_from_players[index]),
        })
    return {
        "captured_at": captured_at or _now_iso(),
        "round_wind": "east",
        "dealer_index": snapshot.dealer_index,
        "current_player": snapshot.current_player,
        "honba": snapshot.honba or 0,
        "riichi_sticks": snapshot.riichi_sticks or 0,
        "dora_indicators": list(snapshot.dora_indicators),
        "self_index": snapshot.self_index,
        "hand": list(snapshot.hand),
        "own_melds": [list(meld) for meld in snapshot.melds],
        "own_meld_types": list(snapshot.meld_types),
        "last_discard_event": list(snapshot.last_discard_event) if snapshot.last_discard_event else None,
        "players": players,
    }


class GameRecordWriter:
    """1対局セッションを1 JSONへ、更新のたびに原子的に保存する。"""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._path: Optional[Path] = None
        self._record: Optional[Dict[str, Any]] = None
        self._previous: Optional[TableSnapshot] = None

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def append(self, snapshot: TableSnapshot) -> Optional[Path]:
        with self._lock:
            if snapshot == self._previous:
                return self._path
            if self._record is not None and self._is_new_game(snapshot):
                self._finish_locked()
            if self._record is None:
                self._start_locked(snapshot)
            assert self._record is not None and self._path is not None
            event = snapshot_to_record(snapshot)
            self._record["updated_at"] = event["captured_at"]
            self._record["events"].append(event)
            self._previous = snapshot
            self._write_locked()
            return self._path

    def close(self) -> None:
        with self._lock:
            self._finish_locked()

    def _start_locked(self, snapshot: TableSnapshot) -> None:
        started = datetime.now().astimezone()
        stamp = started.strftime("%Y%m%d_%H%M%S_%f")[:-3]
        candidate = self.output_dir / f"game_{stamp}.json"
        suffix = 2
        while candidate.exists():
            candidate = self.output_dir / f"game_{stamp}_{suffix}.json"
            suffix += 1
        self._path = candidate
        self._record = {
            "schema": "star-resonance-mahjong-record",
            "version": 1,
            "started_at": started.isoformat(timespec="milliseconds"),
            "updated_at": started.isoformat(timespec="milliseconds"),
            "completed": False,
            "table_guid": snapshot.table_guid,
            "events": [],
        }

    def _is_new_game(self, snapshot: TableSnapshot) -> bool:
        previous = self._previous
        if previous is None:
            return False
        if snapshot.table_guid and previous.table_guid and snapshot.table_guid != previous.table_guid:
            return True
        # 東1局・全員初期点・河と副露が空へ戻った場合のみ安全側で分割する。
        pristine = (
            snapshot.dealer_index == 0
            and snapshot.scores == (25000, 25000, 25000, 25000)
            and not any(snapshot.discards)
            and not any(snapshot.player_melds)
            and (snapshot.honba or 0) == 0
            and (snapshot.riichi_sticks or 0) == 0
        )
        previous_progressed = any(previous.discards) or any(previous.player_melds) or previous.scores != snapshot.scores
        return pristine and previous_progressed

    def _finish_locked(self) -> None:
        if self._record is None:
            return
        self._record["completed"] = True
        self._record["ended_at"] = _now_iso()
        self._record["updated_at"] = self._record["ended_at"]
        self._write_locked()
        self._record = None
        self._path = None
        self._previous = None

    def _write_locked(self) -> None:
        assert self._record is not None and self._path is not None
        temporary = self._path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(self._record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self._path)