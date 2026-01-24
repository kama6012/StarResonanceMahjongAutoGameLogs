# Copyright (c) 2026 yuzeis
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import argparse
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    from mahjong_proto_smart_showdata import parse_bin
except ImportError:
    print("错误: 请确保 mahjong_proto_smart_showdata.py 在同一目录下")
    sys.exit(1)


# 麻将牌映射表
TILE_MAP = {}

def init_tile_map():
    """初始化136张实体牌的映射表"""
    global TILE_MAP
    
    # 万子 (m) 0-35
    for num in range(1, 10):
        for copy in range(4):
            TILE_MAP[(num - 1) * 4 + copy] = f"{num}m"
    
    # 筒子 (p) 36-71
    for num in range(1, 10):
        for copy in range(4):
            TILE_MAP[36 + (num - 1) * 4 + copy] = f"{num}p"
    
    # 索子 (s) 72-107
    for num in range(1, 10):
        for copy in range(4):
            TILE_MAP[72 + (num - 1) * 4 + copy] = f"{num}s"
    
    # 字牌 (z) 108-135
    honors = ['东', '南', '西', '北', '白', '发', '中']
    for idx, honor in enumerate(honors):
        for copy in range(4):
            TILE_MAP[108 + idx * 4 + copy] = f"{idx+1}z({honor})"


def tile_id_to_str(tile_id: int) -> str:
    """将实体牌ID转换为可读字符串"""
    return TILE_MAP.get(tile_id, f"未知({tile_id})")


def tile_id_to_sort_key(tile_id: int) -> tuple:
    """生成排序键，按 mpsz 顺序排列"""
    if 0 <= tile_id <= 35:
        return (0, tile_id // 4 + 1, tile_id)
    elif 36 <= tile_id <= 71:
        return (1, (tile_id - 36) // 4 + 1, tile_id)
    elif 72 <= tile_id <= 107:
        return (2, (tile_id - 72) // 4 + 1, tile_id)
    elif 108 <= tile_id <= 135:
        return (3, (tile_id - 108) // 4 + 1, tile_id)
    return (99, 99, tile_id)


def format_hand_grouped(cards: List[int]) -> str:
    """按牌种分组显示手牌，返回格式: 13m25p789s1234567z"""
    cards = sorted(cards, key=tile_id_to_sort_key)
    groups = {'m': [], 'p': [], 's': [], 'z': []}
    
    for tile_id in cards:
        if 0 <= tile_id <= 35:
            groups['m'].append(str(tile_id // 4 + 1))
        elif 36 <= tile_id <= 71:
            groups['p'].append(str((tile_id - 36) // 4 + 1))
        elif 72 <= tile_id <= 107:
            groups['s'].append(str((tile_id - 72) // 4 + 1))
        elif 108 <= tile_id <= 135:
            groups['z'].append(str((tile_id - 108) // 4 + 1))
    
    result = []
    for suit in ['m', 'p', 's', 'z']:
        if groups[suit]:
            result.append(''.join(groups[suit]) + suit)
    
    return ''.join(result)


def format_melds(melds: List[Dict[str, Any]]) -> str:
    """格式化副露（吃/碰/杠）"""
    if not melds:
        return ""
    
    meld_strs = []
    for meld in melds:
        cards = meld.get('Cards', [])
        if not cards:
            continue
        
        groups = {'m': [], 'p': [], 's': [], 'z': []}
        for tile_id in sorted(cards):
            if 0 <= tile_id <= 35:
                groups['m'].append(str(tile_id // 4 + 1))
            elif 36 <= tile_id <= 71:
                groups['p'].append(str((tile_id - 36) // 4 + 1))
            elif 72 <= tile_id <= 107:
                groups['s'].append(str((tile_id - 72) // 4 + 1))
            elif 108 <= tile_id <= 135:
                groups['z'].append(str((tile_id - 108) // 4 + 1))
        
        parts = []
        for suit in ['m', 'p', 's', 'z']:
            if groups[suit]:
                parts.append(''.join(groups[suit]) + suit)
        
        if parts:
            meld_strs.append(''.join(parts))
    
    return ''.join(meld_strs)


def format_hand(cards: List[int], melds: List[Dict[str, Any]] = None) -> str:
    """格式化手牌显示"""
    if not cards:
        return "无牌"
    
    cards = sorted(cards, key=tile_id_to_sort_key)
    tiles = [tile_id_to_str(c) for c in cards]
    grouped = format_hand_grouped(cards)
    
    if melds:
        melds_str = format_melds(melds)
        if melds_str:
            grouped = f"{grouped} # {melds_str}"
    
    return f"{' '.join(tiles)}\n分组: {grouped}"


def extract_hand_cards(data: Dict[str, Any]) -> Optional[Tuple[List[int], List[Dict[str, Any]]]]:
    """从解析的数据中提取手牌和副露"""
    data_obj = data.get('data', {})
    
    # 策略1: PlayerSelf.Operation.Cards
    player_self = data_obj.get('PlayerSelf')
    if player_self:
        operation = player_self.get('Operation')
        if operation and 'Cards' in operation:
            cards = operation.get('Cards', [])
            melds = operation.get('OpenMelds', [])
            if cards:
                return (cards, melds)
        
        if 'Cards' in player_self:
            cards = player_self.get('Cards', [])
            melds = player_self.get('OpenMelds', [])
            if cards:
                return (cards, melds)
    
    # 策略2: Players[].Cards
    for player in data_obj.get('Players', []):
        if 'Cards' in player:
            cards = player.get('Cards', [])
            melds = player.get('OpenMelds', [])
            if cards:
                return (cards, melds)
    
    # 策略3: Operation.Cards
    operation = data_obj.get('Operation')
    if operation and 'Cards' in operation:
        cards = operation.get('Cards', [])
        melds = operation.get('OpenMelds', [])
        if cards:
            return (cards, melds)
    
    return None


def monitor_file(file_path: str, watch: bool = False, interval: float = 1.0, clean: bool = False):
    """监控文件并输出手牌"""
    init_tile_map()
    last_mtime = None
    last_state = None
    
    if not clean:
        print(f"{'='*60}")
        print(f"麻将手牌监控器")
        print(f"文件: {file_path}")
        print(f"模式: {'持续监控' if watch else '单次解析'}")
        print(f"{'='*60}\n")
    
    try:
        while True:
            path = Path(file_path)
            
            if not path.exists():
                if not clean:
                    print(f"文件不存在: {file_path}")
                if not watch:
                    break
                time.sleep(interval)
                continue
            
            current_mtime = path.stat().st_mtime
            
            if last_mtime is not None and current_mtime == last_mtime:
                if not watch:
                    break
                time.sleep(interval)
                continue
            
            last_mtime = current_mtime
            
            try:
                result = parse_bin(file_path, max_offset=512, allow_zstd=True)
                hand_data = extract_hand_cards(result)
                
                if hand_data is None:
                    if not clean:
                        print("未找到手牌数据")
                    if not watch:
                        break
                    time.sleep(interval)
                    continue
                
                cards, melds = hand_data
                current_state = (tuple(cards), str(melds))
                
                if current_state == last_state:
                    if not watch:
                        break
                    time.sleep(interval)
                    continue
                
                last_state = current_state
                
                if clean:
                    grouped = format_hand_grouped(cards)
                    if melds:
                        melds_str = format_melds(melds)
                        if melds_str:
                            grouped = f"{grouped}#{melds_str}"
                    print(grouped)
                else:
                    total_tiles = len(cards)
                    meld_tiles = sum(len(m.get('Cards', [])) for m in melds)
                    
                    print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}]")
                    print(f"手牌数量: {total_tiles} 张")
                    if melds:
                        print(f"副露数量: {len(melds)} 组 ({meld_tiles} 张)")
                        print(f"总计: {total_tiles + meld_tiles} 张")
                    print(f"原始ID: {cards}")
                    if melds:
                        for i, meld in enumerate(melds, 1):
                            print(f"副露 {i}: {meld.get('Cards', [])}")
                    print(f"\n{format_hand(cards, melds)}")
                    print(f"{'-'*60}")
                
            except Exception as e:
                if not clean:
                    print(f"解析错误: {e}")
                if not watch:
                    break
            
            if not watch:
                break
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        if not clean:
            print("\n\n监控已停止")


def main():
    parser = argparse.ArgumentParser(description="麻将手牌实时监控器")
    parser.add_argument("path", nargs='?', help="输入的二进制文件路径")
    parser.add_argument("--watch", action="store_true", help="持续监控文件变化")
    parser.add_argument("--interval", type=float, default=1.0, help="监控间隔（秒）")
    parser.add_argument("--clean", action="store_true", help="纯净模式：只输出紧凑牌型")
    
    args = parser.parse_args()
    
    if not args.path:
        parser.print_help()
        return
    
    monitor_file(args.path, watch=args.watch, interval=args.interval, clean=args.clean)


if __name__ == "__main__":
    main()
