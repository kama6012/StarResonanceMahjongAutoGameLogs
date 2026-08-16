"""通信スナップショットをGUI向けの追跡表示モデルへ変換する。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from analysis.tiles import format_melds, format_tiles
from protocol import TableSnapshot


WINDS = ("東", "南", "西", "北")
RIICHI_LABELS = ("—", "宣言", "成立")


@dataclass(frozen=True)
class PlayerView:
    index: int
    score: int
    seat_wind: str
    river: str
    melds: str
    riichi: str
    is_self: bool
    is_dealer: bool
    is_current: bool

    @property
    def markers(self) -> str:
        labels = []
        if self.is_self:
            labels.append("自分")
        if self.is_dealer:
            labels.append("親")
        if self.is_current:
            labels.append("手番")
        if self.riichi != "—":
            labels.append(f"立直{self.riichi}")
        return " / ".join(labels) or "—"


@dataclass(frozen=True)
class TableView:
    snapshot: TableSnapshot
    round_label: str
    honba: int
    riichi_sticks: int
    dealer_label: str
    current_label: str
    dora: str
    hand: str
    own_melds: str
    players: Tuple[PlayerView, PlayerView, PlayerView, PlayerView]


class SessionCoordinator:
    """卓状態を表示専用モデルへ整形し、同一更新を重複排除する。"""

    def __init__(self) -> None:
        self.previous: Optional[TableView] = None
        self._dealer_index: Optional[int] = None
        self._honba = 0
        self._riichi_sticks = 0

    def accept(self, snapshot: TableSnapshot) -> Optional[TableView]:
        dealer = snapshot.dealer_index
        if dealer is None:
            east_players = [index for index, wind in enumerate(snapshot.seat_winds) if wind == 0]
            if len(east_players) == 1:
                dealer = east_players[0]
            else:
                dealer = self._dealer_index
        if dealer is not None and 0 <= dealer < 4:
            self._dealer_index = dealer
        else:
            dealer = self._dealer_index
        kyoku = dealer + 1 if dealer is not None else None
        if snapshot.honba is not None:
            self._honba = snapshot.honba
        if snapshot.riichi_sticks is not None:
            self._riichi_sticks = snapshot.riichi_sticks
        # 対象ゲームのルールでは場風は常に東。
        round_label = f"東{kyoku}局" if kyoku is not None else "東場"
        players = tuple(
            PlayerView(
                index=index,
                score=snapshot.scores[index],
                seat_wind=WINDS[snapshot.seat_winds[index]] if 0 <= snapshot.seat_winds[index] < 4 else "?",
                river=" ".join(format_tiles((tile,)) for tile in snapshot.discards[index]) or "—",
                melds=format_melds(snapshot.player_melds[index], snapshot.player_meld_types[index]),
                riichi=RIICHI_LABELS[min(snapshot.riichi_states[index], 2)],
                is_self=index == snapshot.self_index,
                is_dealer=index == dealer,
                is_current=index == snapshot.current_player,
            )
            for index in range(4)
        )
        view = TableView(
            snapshot=snapshot,
            round_label=round_label,
            honba=self._honba,
            riichi_sticks=self._riichi_sticks,
            dealer_label=f"プレイヤー {dealer + 1}" if dealer is not None else "不明",
            current_label=f"プレイヤー {snapshot.current_player + 1}" if snapshot.current_player is not None else "不明",
            dora=" ".join(format_tiles((tile,)) for tile in snapshot.dora_indicators) or "—",
            hand=format_tiles(snapshot.hand) or "—",
            own_melds=format_melds(snapshot.melds, snapshot.meld_types),
            players=players,  # type: ignore[arg-type]
        )
        if view == self.previous:
            return None
        self.previous = view
        return view
