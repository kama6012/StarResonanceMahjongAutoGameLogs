"""麻雀リアルタイム卓追跡アプリのエントリポイント。"""

from analysis.tiles import (
    format_melds as render_melds, render_hand as render_compact, tile_id_to_str,
)
from capture import TcpPayloadOrderer
from app.runtime import GUI, configure_console_encoding, main

if __name__ == "__main__":
    main()
