"""136枚方式の牌IDを追跡GUI向けに整形する。"""
from __future__ import annotations

import re
from typing import Iterable, Sequence

RED_FIVE_IDS = {19: "m", 55: "p", 91: "s"}
HONORS = ("东", "南", "西", "北", "白", "发", "中")


def tile_id_to_sort_key(tile_id: int) -> tuple[int, int, int]:
    if 0 <= tile_id <= 35:
        return 0, tile_id // 4 + 1, tile_id
    if 36 <= tile_id <= 71:
        return 1, (tile_id - 36) // 4 + 1, tile_id
    if 72 <= tile_id <= 107:
        return 2, (tile_id - 72) // 4 + 1, tile_id
    if 108 <= tile_id <= 135:
        return 3, (tile_id - 108) // 4 + 1, tile_id
    return 99, 99, tile_id


def tile_id_to_str(tile_id: int) -> str:
    if tile_id in RED_FIVE_IDS:
        return f"r5{RED_FIVE_IDS[tile_id]}"
    if 0 <= tile_id <= 35:
        return f"{tile_id // 4 + 1}m"
    if 36 <= tile_id <= 71:
        return f"{(tile_id - 36) // 4 + 1}p"
    if 72 <= tile_id <= 107:
        return f"{(tile_id - 72) // 4 + 1}s"
    if 108 <= tile_id <= 135:
        rank = (tile_id - 108) // 4
        return f"{rank + 1}z({HONORS[rank]})"
    return f"不明（{tile_id}）"


def format_tiles(cards: Iterable[int]) -> str:
    """同色の牌をまとめ、赤5にはrを付ける。"""
    groups: dict[str, list[str]] = {suit: [] for suit in "mpsz"}
    for tile_id in sorted(cards, key=tile_id_to_sort_key):
        if tile_id in RED_FIVE_IDS:
            groups[RED_FIVE_IDS[tile_id]].append("r5")
        elif 0 <= tile_id <= 35:
            groups["m"].append(str(tile_id // 4 + 1))
        elif 36 <= tile_id <= 71:
            groups["p"].append(str((tile_id - 36) // 4 + 1))
        elif 72 <= tile_id <= 107:
            groups["s"].append(str((tile_id - 72) // 4 + 1))
        elif 108 <= tile_id <= 135:
            groups["z"].append(str((tile_id - 108) // 4 + 1))

    result = []
    for suit in "mpsz":
        values = groups[suit]
        if not values:
            continue
        has_red = "r5" in values
        digits = "".join("5" if value == "r5" else value for value in values)
        if has_red:
            position = digits.find("5")
            digits = digits[:position] + "r" + digits[position:]
        result.append(digits + suit)
    return "".join(result)


def format_melds(
    melds: Sequence[Sequence[int]],
    meld_types: Sequence[int] = (),
    *,
    empty: str = "—",
    separator: str = " / ",
) -> str:
    rendered = []
    for index, meld in enumerate(melds):
        if not meld:
            continue
        part = format_tiles(meld)
        if index < len(meld_types) and meld_types[index] == 3:
            part = re.sub(r"([mpsz])", lambda match: match.group(1).upper(), part)
        rendered.append(part)
    return separator.join(rendered) or empty


def render_hand(cards, melds, meld_types=()) -> str:
    result = format_tiles(cards)
    rendered_melds = format_melds(
        melds, meld_types, empty="", separator=""
    )
    return result + ("#" + rendered_melds if rendered_melds else "")
