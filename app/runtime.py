"""リアルタイム卓追跡GUIとパケット捕捉の組み立て。"""
from __future__ import annotations

import argparse
import shutil
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from app.game_record import GameRecordWriter
from app.session import SessionCoordinator, TableView
from capture import TcpPayloadOrderer
from packet_capture_bin import PacketCapture
from protocol import MahjongStateTracker, StreamDecoder


def configure_console_encoding() -> None:
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass


class GUI:
    """通信から復元した卓状態だけを表示する追跡GUI。"""

    def __init__(self, *, topmost: bool = True):
        import tkinter as tk
        from tkinter import ttk

        self._lock = threading.Lock()
        self._closed = False
        self._pending_view: Optional[TableView] = None
        self._pending_status: Optional[str] = None
        self.session = SessionCoordinator()

        self.root = tk.Tk()
        self.root.title("Star Resonance 麻雀リアルタイム追跡")
        self.root.geometry("1080x780")
        self.root.minsize(900, 650)
        try:
            self.root.attributes("-topmost", bool(topmost))
        except Exception:
            pass

        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        status = ttk.Frame(main)
        status.pack(fill="x", pady=(0, 8))
        self.var_status = tk.StringVar(value="捕捉準備中…")
        ttk.Label(status, textvariable=self.var_status).pack(side="left")
        self.var_topmost = tk.BooleanVar(value=bool(topmost))
        ttk.Checkbutton(status, text="常に最前面", variable=self.var_topmost,
                        command=self._toggle_topmost).pack(side="right")

        round_frame = ttk.LabelFrame(main, text="局情報", padding=8)
        round_frame.pack(fill="x", pady=(0, 8))
        self.var_round = tk.StringVar(value="局: —")
        self.var_dealer = tk.StringVar(value="親: —")
        self.var_current = tk.StringVar(value="手番: —")
        self.var_honba = tk.StringVar(value="本場: —")
        self.var_sticks = tk.StringVar(value="供託: —")
        self.var_dora = tk.StringVar(value="ドラ表示牌: —")
        for column, variable in enumerate((self.var_round, self.var_dealer, self.var_current,
                                           self.var_honba, self.var_sticks, self.var_dora)):
            ttk.Label(round_frame, textvariable=variable, font=("Yu Gothic UI", 10, "bold")).grid(
                row=0, column=column, padx=(0, 18), sticky="w"
            )

        hand_frame = ttk.LabelFrame(main, text="自分の手牌", padding=10)
        hand_frame.pack(fill="x", pady=(0, 8))
        self.var_hand = tk.StringVar(value="—")
        self.var_own_melds = tk.StringVar(value="副露: —")
        ttk.Label(hand_frame, textvariable=self.var_hand, font=("Consolas", 18, "bold")).pack(anchor="w")
        ttk.Label(hand_frame, textvariable=self.var_own_melds, font=("Consolas", 12)).pack(anchor="w", pady=(6, 0))

        players = ttk.Frame(main)
        players.pack(fill="both", expand=True)
        players.columnconfigure(0, weight=1)
        players.columnconfigure(1, weight=1)
        players.rowconfigure(0, weight=1)
        players.rowconfigure(1, weight=1)
        self.player_vars = []
        for index in range(4):
            frame = ttk.LabelFrame(players, text=f"プレイヤー {index + 1}", padding=9)
            frame.grid(row=index // 2, column=index % 2, sticky="nsew", padx=4, pady=4)
            marker = tk.StringVar(value="状態: —")
            score = tk.StringVar(value="点数: —　席風: —　立直: —")
            river = tk.StringVar(value="河: —")
            melds = tk.StringVar(value="副露: —")
            ttk.Label(frame, textvariable=marker, font=("Yu Gothic UI", 11, "bold")).pack(anchor="w")
            ttk.Label(frame, textvariable=score).pack(anchor="w", pady=(3, 8))
            ttk.Label(frame, textvariable=river, font=("Consolas", 11), wraplength=470).pack(anchor="w")
            ttk.Label(frame, textvariable=melds, font=("Consolas", 11), wraplength=470).pack(anchor="w", pady=(8, 0))
            self.player_vars.append((frame, marker, score, river, melds))

        self.var_updated = tk.StringVar(value="最終卓更新: —")
        ttk.Label(main, textvariable=self.var_updated).pack(anchor="e", pady=(6, 0))

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._tick)

    def _toggle_topmost(self) -> None:
        try:
            self.root.attributes("-topmost", bool(self.var_topmost.get()))
        except Exception:
            pass

    def _on_close(self) -> None:
        self._closed = True
        self.root.destroy()

    def is_closed(self) -> bool:
        return self._closed

    def set_table_snapshot(self, snapshot) -> None:
        view = self.session.accept(snapshot)
        if view is not None:
            with self._lock:
                self._pending_view = view

    def post_status(self, text: str) -> None:
        with self._lock:
            self._pending_status = text

    def _render_view(self, view: TableView) -> None:
        self.var_round.set(f"局: {view.round_label}")
        self.var_dealer.set(f"親: {view.dealer_label}")
        self.var_current.set(f"手番: {view.current_label}")
        self.var_honba.set(f"本場: {view.honba}")
        self.var_sticks.set(f"供託: {view.riichi_sticks}")
        self.var_dora.set(f"ドラ表示牌: {view.dora}")
        self.var_hand.set(view.hand)
        self.var_own_melds.set(f"副露: {view.own_melds}")
        for player, variables in zip(view.players, self.player_vars):
            frame, marker, score, river, melds = variables
            frame.configure(text=f"プレイヤー {player.index + 1} [{player.seat_wind}家]")
            marker.set(f"状態: {player.markers}")
            score.set(f"点数: {player.score:,}　席風: {player.seat_wind}　立直: {player.riichi}")
            river.set(f"河: {player.river}")
            melds.set(f"副露: {player.melds}")
        self.var_updated.set(f"最終卓更新: {datetime.now().strftime('%H:%M:%S')}")

    def _tick(self) -> None:
        if self._closed:
            return
        try:
            with self._lock:
                view, status = self._pending_view, self._pending_status
                self._pending_view = None
                self._pending_status = None
            if status is not None:
                self.var_status.set(status)
            if view is not None:
                self._render_view(view)
        except Exception:
            traceback.print_exc()
        finally:
            if not self._closed:
                self.root.after(80, self._tick)

    def loop(self) -> None:
        self.root.mainloop()


def main() -> None:
    configure_console_encoding()
    parser = argparse.ArgumentParser(description="Star Resonance麻雀リアルタイム卓追跡")
    parser.add_argument("--name", default="StarASIA_STEAM.exe", help="対象プロセス名")
    parser.add_argument("--out", default="./bins", help="一時キャプチャbin出力先")
    parser.add_argument("--records", default="./records", help="構造化牌譜JSON出力先")
    parser.add_argument("--iface", default=None, help="捕捉インターフェース")
    parser.add_argument("--poll", type=float, default=0.3, help="ポート確認間隔")
    parser.add_argument("--udp", action="store_true", help="UDPも捕捉する")
    parser.add_argument("--no-external-only", action="store_true", help="内部通信も捕捉する")
    parser.add_argument("--no-decompress", action="store_true", help="zstd自動展開を無効化")
    parser.add_argument("--no-topmost-ui", action="store_true", help="常に最前面を無効化")
    parser.add_argument("--no-save-records", action="store_true", help="構造化牌譜JSONを保存しない")
    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    record_writer = None if args.no_save_records else GameRecordWriter(Path(args.records).resolve())
    ui = GUI(topmost=not args.no_topmost_ui)
    server_streams: Dict[str, StreamDecoder] = {}
    server_orderers: Dict[str, TcpPayloadOrderer] = {}
    tracker = MahjongStateTracker()

    def on_bin(info: Dict[str, Any]) -> None:
        payload = info.get("payload")
        if info.get("kind") != "TCP" or not payload:
            return
        src, dst = str(info.get("src", "")), str(info.get("dst", ""))
        try:
            src_port, dst_port = int(src.rsplit(":", 1)[1]), int(dst.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return
        if 5003 not in (src_port, dst_port) or src_port in cap.local_tcp_ports():
            return
        try:
            seq = int(info["seq"])
        except (KeyError, TypeError, ValueError):
            return
        flow = f"{src}>{dst}"
        ordered = server_orderers.setdefault(flow, TcpPayloadOrderer()).feed(seq, payload)
        if not ordered:
            return
        for message in server_streams.setdefault(flow, StreamDecoder()).feed(ordered):
            snapshot = tracker.feed_message(message)
            if snapshot is not None:
                if record_writer is not None:
                    record_writer.append(snapshot)
                ui.set_table_snapshot(snapshot)

    cap = PacketCapture(
        interface=args.iface,
        process_name=args.name,
        output_dir=str(out_dir),
        poll_interval=args.poll,
        include_udp=bool(args.udp),
        external_only=not args.no_external_only,
        auto_decompress=not args.no_decompress,
        tcp_watch_ports={5003},
        write_files=True,
    )
    try:
        cap.start(callback=on_bin)
        status = cap.status_snapshot()
        ports = ", ".join(map(str, status.tcp_ports)) or "5003（固定監視）"
        ui.post_status(
            f"捕捉中 | IF: {cap.interface} | PID: {status.pid if status.pid is not None else '未検出'} | TCP: {ports}"
        )

        def watchdog() -> None:
            while not ui.is_closed():
                if cap.last_error:
                    ui.post_status(f"捕捉エラー: {cap.last_error}")
                    return
                time.sleep(0.5)

        threading.Thread(target=watchdog, daemon=True).start()
    except Exception as exc:
        ui.post_status(f"捕捉開始エラー: {exc}（Npcap・管理者権限・インターフェースを確認）")

    try:
        ui.loop()
    finally:
        cap.stop()
        if record_writer is not None:
            record_writer.close()
        try:
            if out_dir.exists():
                shutil.rmtree(out_dir)
        except OSError:
            pass


if __name__ == "__main__":
    main()