"""保存ストリームのレイヤー構成と検出された卓状態を確認する調査CLI。"""
import argparse
from collections import Counter
from pathlib import Path
import sys

# ファイルパスで直接実行した場合もリポジトリルートをimport対象にする。
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol import MahjongStateTracker, StreamDecoder


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    decoder = StreamDecoder()
    messages = decoder.feed(Path(args.path).read_bytes())
    print("application messages:", len(messages))
    print("opcodes:", Counter(m.opcode for m in messages))
    print("commands:", Counter(m.command for m in messages if m.command is not None))
    tracker = MahjongStateTracker()
    updates = [state for message in messages if (state := tracker.feed_message(message)) is not None]
    print("validated mahjong snapshots:", len(updates))
    if updates:
        print(updates[-1])


if __name__ == "__main__":
    main()