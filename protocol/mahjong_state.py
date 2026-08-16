"""意味制約を満たす麻雀同期だけから卓状態を追跡する。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from mahjong_proto_smart_showdata import ProtobufSmartDecoder


TileList = Tuple[int, ...]
MeldList = Tuple[TileList, ...]


@dataclass(frozen=True)
class TableSnapshot:
    discards: Tuple[TileList, TileList, TileList, TileList]
    dora_indicators: TileList
    player_melds: Tuple[MeldList, MeldList, MeldList, MeldList] = ((), (), (), ())
    player_meld_types: Tuple[TileList, TileList, TileList, TileList] = ((), (), (), ())
    current_player: Optional[int] = None
    hand: TileList = ()
    self_index: Optional[int] = None
    melds: Tuple[TileList, ...] = ()
    meld_types: TileList = ()
    last_discard_event: Optional[Tuple[int, int, int]] = None
    dealer_index: Optional[int] = None
    round_wind: Optional[int] = None
    honba: Optional[int] = None
    riichi_sticks: Optional[int] = None
    scores: Tuple[int, int, int, int] = (25000, 25000, 25000, 25000)
    seat_winds: Tuple[int, int, int, int] = (0, 1, 2, 3)
    riichi_states: Tuple[int, int, int, int] = (0, 0, 0, 0)
    card_counts: Tuple[int, int, int, int] = (13, 13, 13, 13)
    last_draw_flags: Tuple[bool, bool, bool, bool] = (False, False, False, False)
    meld_called_tiles: Tuple[TileList, TileList, TileList, TileList] = ((), (), (), ())
    meld_from_players: Tuple[TileList, TileList, TileList, TileList] = ((), (), (), ())
    table_guid: Optional[str] = None


class _WireError(ValueError):
    pass


def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise _WireError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise _WireError("varint too long")


def _fields(data: bytes) -> List[Tuple[int, int, Any]]:
    result: List[Tuple[int, int, Any]] = []
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        field, wire = key >> 3, key & 7
        if field <= 0:
            raise _WireError("invalid field")
        if wire == 0:
            value, offset = _read_varint(data, offset)
        elif wire == 1:
            if offset + 8 > len(data):
                raise _WireError("truncated fixed64")
            value, offset = data[offset:offset + 8], offset + 8
        elif wire == 2:
            size, offset = _read_varint(data, offset)
            if offset + size > len(data):
                raise _WireError("truncated bytes")
            value, offset = data[offset:offset + size], offset + size
        elif wire == 5:
            if offset + 4 > len(data):
                raise _WireError("truncated fixed32")
            value, offset = data[offset:offset + 4], offset + 4
        else:
            raise _WireError(f"unsupported wire type: {wire}")
        result.append((field, wire, value))
    return result


def _bytes_fields(data: bytes, field: int) -> List[bytes]:
    return [value for number, wire, value in _fields(data) if number == field and wire == 2]


def _varint_field(data: bytes, field: int) -> Optional[int]:
    return next((value for number, wire, value in _fields(data) if number == field and wire == 0), None)


def _packed_varints(data: bytes) -> TileList:
    values = []
    offset = 0
    while offset < len(data):
        value, offset = _read_varint(data, offset)
        values.append(value)
    return tuple(values)


def snapshot_from_world_update(payload: bytes) -> Optional[TableSnapshot]:
    """実対局のworld-updateラッパーから完全な卓スナップショットを抽出する。"""
    try:
        nodes = [payload]
        for field in (1, 3, 3):
            nodes = [child for node in nodes for child in _bytes_fields(node, field)]
        for table in nodes:
            players = _bytes_fields(table, 7)
            if len(players) != 4:
                continue
            by_index: Dict[int, TileList] = {}
            melds_by_index: Dict[int, MeldList] = {}
            meld_types_by_index: Dict[int, TileList] = {}
            scores_by_index: Dict[int, int] = {}
            winds_by_index: Dict[int, int] = {}
            riichi_by_index: Dict[int, int] = {}
            counts_by_index: Dict[int, int] = {}
            draws_by_index: Dict[int, bool] = {}
            called_by_index: Dict[int, TileList] = {}
            from_by_index: Dict[int, TileList] = {}
            for player in players:
                index_value = _varint_field(player, 2)
                index = 0 if index_value is None else index_value
                packed = _bytes_fields(player, 6)
                discards = _packed_varints(packed[0]) if packed else ()
                public_melds = []
                public_meld_types = []
                public_called_tiles = []
                public_from_players = []
                for meld in _bytes_fields(player, 7):
                    meld_cards = _bytes_fields(meld, 2)
                    cards = _packed_varints(meld_cards[0]) if meld_cards else ()
                    if not 3 <= len(cards) <= 4 or any(tile > 135 for tile in cards):
                        break
                    public_melds.append(cards)
                    # protobuf既定値0はチー、1はポン、3は暗槓、4は加槓。
                    meld_type = _varint_field(meld, 1)
                    public_meld_types.append(0 if meld_type is None else meld_type)
                    called = _varint_field(meld, 3)
                    source = _varint_field(meld, 4)
                    public_called_tiles.append(255 if called is None else called)
                    public_from_players.append(255 if source is None else source)
                else:
                    melds_by_index[index] = tuple(public_melds)
                    meld_types_by_index[index] = tuple(public_meld_types)
                    called_by_index[index] = tuple(public_called_tiles)
                    from_by_index[index] = tuple(public_from_players)
                if (
                    not 0 <= index < 4
                    or index in by_index
                    or index not in melds_by_index
                    or index not in meld_types_by_index
                    or len(discards) > 30
                    or any(tile > 135 for tile in discards)
                ):
                    break
                by_index[index] = discards
                scores_by_index[index] = _varint_field(player, 3) or 0
                winds_by_index[index] = _varint_field(player, 4) or 0
                riichi_by_index[index] = _varint_field(player, 5) or 0
                counts_by_index[index] = _varint_field(player, 8) or 0
                draws_by_index[index] = bool(_varint_field(player, 9) or 0)
            if len(by_index) != 4:
                continue
            dora_parts = _bytes_fields(table, 2)
            doras = _packed_varints(dora_parts[0]) if dora_parts else ()
            # CurrentIndex=0はprotobuf既定値なのでwire上から省略される。
            # 卓が有効（ドラまたは配牌が存在）なら欠落はプレイヤー0を意味する。
            current = _varint_field(table, 3)
            if current is None and doras:
                current = 0
            if len(doras) > 5 or any(tile > 135 for tile in doras) or (current is not None and not 0 <= current < 4):
                continue
            # 自分の非公開状態はfield 8（通常更新）または9（局開始時）にあり、
            # その最初の子messageのfield 10が物理牌IDのpacked list。
            hand: TileList = ()
            self_index: Optional[int] = None
            melds: Tuple[TileList, ...] = ()
            meld_types: TileList = ()
            last_discard_event: Optional[Tuple[int, int, int]] = None
            actions = _bytes_fields(table, 1)
            if actions:
                action = actions[0]
                if _varint_field(action, 1) == 1:
                    actor = _varint_field(action, 2)
                    tile = _varint_field(action, 3)
                    sequence = _varint_field(action, 5)
                    actor = 0 if actor is None else actor
                    if 0 <= actor < 4 and tile is not None and 0 <= tile <= 135:
                        last_discard_event = (actor, tile, 0 if sequence is None else sequence)
            for private_field in (8, 9):
                for private in _bytes_fields(table, private_field):
                    owners = _bytes_fields(private, 1)
                    if not owners:
                        continue
                    owner = owners[0]
                    owner_index = _varint_field(owner, 2)
                    # protobufの数値既定値0はwire上から省略される。
                    # field 2がない場合は不明ではなくプレイヤー0を意味する。
                    owner_index = 0 if owner_index is None else owner_index
                    if 0 <= owner_index < 4:
                        self_index = owner_index
                    parsed_melds = []
                    parsed_meld_types = []
                    for meld in _bytes_fields(owner, 7):
                        meld_cards = _bytes_fields(meld, 2)
                        cards = _packed_varints(meld_cards[0]) if meld_cards else ()
                        if 3 <= len(cards) <= 4 and all(tile <= 135 for tile in cards):
                            parsed_melds.append(cards)
                            meld_type = _varint_field(meld, 1)
                            parsed_meld_types.append(0 if meld_type is None else meld_type)
                    melds = tuple(parsed_melds)
                    meld_types = tuple(parsed_meld_types)
                    packed_hands = _bytes_fields(owner, 10)
                    if not packed_hands:
                        continue
                    candidate = _packed_varints(packed_hands[0])
                    if 1 <= len(candidate) <= 14 and all(tile <= 135 for tile in candidate):
                        hand = candidate
                        break
                if hand:
                    break
            # world-update内の卓はMahjongSyncOpMessage相当。
            # field 4は供託、field 5は本場であり、親は席風0（東家）から求める。
            east_players = [index for index, wind in winds_by_index.items() if wind == 0]
            dealer_index = east_players[0] if len(east_players) == 1 else None
            return TableSnapshot(
                discards=tuple(by_index[i] for i in range(4)),
                dora_indicators=doras,
                player_melds=tuple(melds_by_index[i] for i in range(4)),
                player_meld_types=tuple(meld_types_by_index[i] for i in range(4)),
                current_player=current,
                hand=hand,
                self_index=self_index,
                melds=melds,
                meld_types=meld_types,
                last_discard_event=last_discard_event,
                dealer_index=dealer_index,
                round_wind=0,
                # この同期は完全状態。protobuf既定値の省略は0を意味する。
                honba=_varint_field(table, 5) or 0,
                riichi_sticks=_varint_field(table, 4) or 0,
                scores=tuple(scores_by_index[i] for i in range(4)),
                seat_winds=tuple(winds_by_index[i] for i in range(4)),
                riichi_states=tuple(riichi_by_index[i] for i in range(4)),
                card_counts=tuple(counts_by_index[i] for i in range(4)),
                last_draw_flags=tuple(draws_by_index[i] for i in range(4)),
                meld_called_tiles=tuple(called_by_index[i] for i in range(4)),
                meld_from_players=tuple(from_by_index[i] for i in range(4)),
            )  # type: ignore[arg-type]
    except _WireError:
        return None
    return None


def _valid_tiles(value: Any, maximum: int) -> Optional[TileList]:
    if not isinstance(value, list) or len(value) > maximum:
        return None
    try:
        tiles = tuple(int(x) for x in value)
    except (TypeError, ValueError):
        return None
    return tiles if all(0 <= x <= 135 for x in tiles) else None


def snapshot_from_decoded(data: Dict[str, Any]) -> Optional[TableSnapshot]:
    """4人分の整合したスナップショットのみ採用し、部分的な偶然一致を拒否する。"""
    players = data.get("Players")
    if not isinstance(players, list) or len(players) != 4:
        return None
    by_index: Dict[int, TileList] = {}
    for player in players:
        if not isinstance(player, dict):
            return None
        index = player.get("PlayerIndex")
        drops = _valid_tiles(player.get("DropCards"), 30)
        if not isinstance(index, int) or not 0 <= index < 4 or drops is None or index in by_index:
            return None
        by_index[index] = drops
    if len(by_index) != 4:
        return None
    doras = _valid_tiles(data.get("Doras"), 5)
    if doras is None:
        return None
    current = data.get("CurrentIndex")
    if current is not None and (not isinstance(current, int) or not 0 <= current < 4):
        return None
    return TableSnapshot(tuple(by_index[i] for i in range(4)), doras, current_player=current)  # type: ignore[arg-type]


class MahjongStateTracker:
    """protobuf境界が確定した候補だけをデコードし、卓状態の更新を返す。"""

    CANDIDATES = ("Zproto.MahjongSyncMessage", "Zproto.MahjongSyncOpMessage")

    def __init__(self) -> None:
        self._decoder = ProtobufSmartDecoder(max_depth=10)
        self.snapshot: Optional[TableSnapshot] = None

    def feed_protobuf(self, payload: bytes) -> Optional[TableSnapshot]:
        snapshot = snapshot_from_world_update(payload)
        if snapshot is not None:
            if snapshot != self.snapshot:
                self.snapshot = snapshot
                return snapshot
            return None
        for message_type in self.CANDIDATES:
            decoded = self._decoder.decode_as(message_type, payload, limit=len(payload))
            if decoded.fatal or decoded.end_pos != len(payload):
                continue
            snapshot = snapshot_from_decoded(decoded.obj)
            if snapshot is not None and snapshot != self.snapshot:
                self.snapshot = snapshot
                return snapshot
        return None

    def feed_message(self, message: Any) -> Optional[TableSnapshot]:
        return self.feed_protobuf(message.protobuf) if getattr(message, "protobuf", b"") else None