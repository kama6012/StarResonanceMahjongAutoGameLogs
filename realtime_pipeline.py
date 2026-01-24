# Copyright (c) 2026 yuzeis
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import argparse
import subprocess
import threading
import time
import sys
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from packet_capture_bin import PacketCapture
from mahjong_proto_smart_showdata import parse_bin as parse_pb_bin


def resource_path(name: str) -> Path:
    """获取资源路径（兼容 PyInstaller）"""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / name
    return Path(__file__).resolve().parent / name


def _load_hand_monitor():
    """动态加载手牌监控模块"""
    import importlib.util
    
    if getattr(sys, "frozen", False):
        here = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    else:
        here = Path(__file__).resolve().parent

    for name in ("mahjong-hand-monitor.py", "mahjong_hand_monitor.py"):
        p = here / name
        if p.exists():
            spec = importlib.util.spec_from_file_location("handmon", str(p))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    
    raise FileNotFoundError("mahjong_hand_monitor.py not found")


HM = _load_hand_monitor()
HM.init_tile_map()


# 中文牌面映射
HONOR_MAP = {"东": "1z", "南": "2z", "西": "3z", "北": "4z", "白": "5z", "发": "6z", "中": "7z"}
HONOR_ALIASES = {"白板": "白", "发财": "发", "红中": "中"}
SUIT_MAP = {
    "p": "p", "P": "p", "s": "s", "S": "s", "m": "m", "M": "m", "z": "z", "Z": "z",
    "饼": "p", "筒": "p", "饼子": "p", "筒子": "p",
    "条": "s", "索": "s", "条子": "s", "索子": "s",
    "万": "m", "萬": "m",
}


def normalize_tile_spec(text: str) -> str:
    """归一化牌面表示（支持中文）"""
    if not text:
        return ""
    
    t = text.strip()
    for k, v in HONOR_ALIASES.items():
        t = t.replace(k, v)

    out = []
    i = 0
    while i < len(t):
        ch = t[i]
        if ch.isspace() or ch in ",，;；|/\\+":
            i += 1
            continue
        
        if ch in HONOR_MAP:
            out.append(HONOR_MAP[ch])
            i += 1
            continue
        
        if ch.isdigit():
            num = ch
            i += 1
            if num == "0":
                continue
            
            suit = None
            if i < len(t):
                if i + 1 < len(t):
                    two = t[i:i+2]
                    if two in SUIT_MAP:
                        suit = SUIT_MAP[two]
                        i += 2
                if suit is None and i < len(t):
                    one = t[i]
                    if one in SUIT_MAP:
                        suit = SUIT_MAP[one]
                        i += 1
            
            if suit:
                out.append(f"{num}{suit}")
            i += 1
            continue
        
        i += 1
    
    return "".join(out)


def extract_hand(parsed: Dict[str, Any]) -> Optional[Tuple[Tuple[int, ...], Tuple[Tuple[int, ...], ...]]]:
    """提取手牌数据"""
    try:
        cards, melds = HM.extract_hand_cards(parsed)
        cards_t = tuple(int(x) for x in (cards or []))
        
        melds_t = tuple(
            tuple(sorted(int(x) for x in m.get('Cards', [])))
            for m in (melds or [])
            if m.get('Cards')
        )
        
        if cards_t:
            return cards_t, melds_t
    except Exception:
        pass
    return None


def render_compact(cards, melds) -> str:
    """渲染紧凑格式手牌"""
    cards_l = list(cards)
    melds_l = [{"Cards": list(m)} for m in melds]
    s = HM.format_hand_grouped(cards_l)
    
    m = HM.format_melds(melds_l)
    if m:
        s += "#" + m
    
    return s


def total_tiles(cards: Tuple[int, ...], melds: Tuple[Tuple[int, ...], ...]) -> int:
    """计算总牌数"""
    return len(cards) + sum(len(m) for m in melds)


def multiset_change_count(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """计算多重集合变化数量"""
    ca, cb = Counter(a), Counter(b)
    keys = set(ca.keys()) | set(cb.keys())
    return sum(abs(ca.get(k, 0) - cb.get(k, 0)) for k in keys) // 2


def run_helper(helper_path: Path, expr: str, dora_spec: str = None) -> str:
    """运行 mahjong-helper"""
    cmd = [str(helper_path)]
    if dora_spec:
        cmd.append(f"-d={dora_spec}")
    cmd.append(expr)

    try:
        kwargs = {}
        if sys.platform.startswith("win"):
            kwargs["creationflags"] = 0x08000000
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                kwargs["startupinfo"] = si
            except Exception:
                pass

        cp = subprocess.run(cmd, capture_output=True, check=False, timeout=10, **kwargs)
    except subprocess.TimeoutExpired:
        return "[helper] 执行超时"
    except Exception as e:
        return f"[helper] 启动失败: {e}"

    out = (cp.stdout or b"") + (cp.stderr or b"")
    if not out:
        return f"[helper] 无输出 (exit={cp.returncode})"

    for enc in ("utf-8", "gbk", "cp936", "latin1"):
        try:
            return out.decode(enc).rstrip("\r\n")
        except Exception:
            continue
    
    return out.decode("utf-8", errors="replace").rstrip("\r\n")


class GUI:
    """图形界面"""
    
    def __init__(self, *, helper_path: Path, topmost: bool = True):
        import tkinter as tk
        from tkinter import ttk
        
        self.helper_path = resource_path(Path(helper_path).name)
        self._lock = threading.Lock()
        self._pending_text: Optional[str] = None
        self.last_hand: str = ""
        self.dora_spec: str = ""

        self.root = tk.Tk()
        self.root.title("Mahjong Realtime")
        self.root.geometry("980x660")
        
        try:
            self.root.attributes("-topmost", bool(topmost))
        except Exception:
            pass

        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill="both", expand=True)

        # 顶部信息栏
        top = ttk.Frame(frm)
        top.pack(fill="x")

        ttk.Label(top, text="当前牌串：").pack(side="left")
        self.var_hand = tk.StringVar(value="(waiting...)")
        ttk.Label(top, textvariable=self.var_hand, font=("Consolas", 12)).pack(side="left", padx=(6, 12))

        ttk.Label(top, text="宝牌(dora)：").pack(side="left")
        self.var_dora = tk.StringVar(value="(none)")
        ttk.Label(top, textvariable=self.var_dora, font=("Consolas", 11)).pack(side="left")

        self.var_top = tk.BooleanVar(value=bool(topmost))
        ttk.Checkbutton(top, text="置顶", variable=self.var_top, command=self._toggle_topmost).pack(side="right")

        # 输出文本区
        self.txt = tk.Text(frm, wrap="word", height=26)
        self.txt.pack(fill="both", expand=True, pady=(10, 8))

        # 帮助信息
        ttk.Label(
            frm,
            text=(
                "命令：\n"
                "  d 牌   设定宝牌（追加） 例：d 5s / d 1饼 / d 东南白\n"
                "  dc     清空宝牌\n"
                "  fl 牌  副露分析 例：fl 3s / fl 3索 / fl 1饼\n"
                "  h 表达式 / 直接输入表达式：手动分析\n"
                "中文归一化：东南西北白发中=1234567z；饼/筒->p，条/索->s，万->m"
            )
        ).pack(anchor="w")

        # 输入框
        self.ent = ttk.Entry(frm)
        self.ent.pack(fill="x", pady=(6, 0))
        self.ent.bind("<Return>", self._on_enter)

        self.set_latest(
            "已启动（作者：倾城璃梦花吹雪 仅供新手做任务使用）。\n"
            "自动分析：当【手牌+副露】合计=14 时触发。\n"
            "提示：宝牌通过 d 命令追加；dc 可清空。\n"
        )

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._closed = False
        self.root.after(80, self._tick)

    def _toggle_topmost(self):
        try:
            self.root.attributes("-topmost", bool(self.var_top.get()))
        except Exception:
            pass

    def _on_close(self):
        self._closed = True
        self.root.destroy()

    def is_closed(self) -> bool:
        return self._closed

    def set_hand(self, hand: str):
        with self._lock:
            self.last_hand = hand

    def append_dora(self, add_spec: str):
        with self._lock:
            self.dora_spec = (self.dora_spec or "") + add_spec

    def clear_dora(self):
        with self._lock:
            self.dora_spec = ""

    def get_state(self) -> Tuple[str, str]:
        with self._lock:
            return self.last_hand, self.dora_spec

    def set_latest(self, text: str):
        self.txt.delete("1.0", "end")
        self.txt.insert("end", text if text.endswith("\n") else text + "\n")
        self.txt.see("end")

    def post_latest(self, text: str):
        with self._lock:
            self._pending_text = text

    def _tick(self):
        if self._closed:
            return
        
        with self._lock:
            hand = self.last_hand
            dora = self.dora_spec
            pending = self._pending_text
            self._pending_text = None
        
        self.var_hand.set(hand if hand else "(waiting...)")
        self.var_dora.set(dora if dora else "(none)")
        
        if pending is not None:
            self.set_latest(pending)
        
        self.root.after(80, self._tick)

    def _run_helper_async(self, expr: str):
        def worker():
            _, dora = self.get_state()
            try:
                out = run_helper(self.helper_path, expr, dora_spec=(dora or None))
            except Exception as e:
                out = f"[helper] 运行异常: {e}"
            self.post_latest(f"> {self.helper_path.name} {'-d='+dora if dora else ''} {expr}\n\n{out}")
        
        threading.Thread(target=worker, daemon=True).start()

    def _on_enter(self, event=None):
        cmd = (self.ent.get() or "").strip()
        self.ent.delete(0, "end")
        
        if not cmd:
            return
        
        low = cmd.lower()

        if low == "dc":
            self.clear_dora()
            self.set_latest("宝牌(dora) 已清空。")
            return

        if low.startswith("d"):
            arg_raw = cmd[1:].strip()
            if not arg_raw:
                _, dora = self.get_state()
                self.set_latest(f"宝牌(dora) 当前值：{dora if dora else '(none)'}")
                return
            
            add = normalize_tile_spec(arg_raw)
            if not add:
                self.set_latest("d 用法示例：d 5s / d 1饼 / d 东南白")
                return
            
            self.append_dora(add)
            _, dora = self.get_state()
            self.set_latest(f"宝牌已追加：{add}\n当前宝牌：{dora}")
            return

        if not self.helper_path.exists():
            self.set_latest(f"[helper] 未找到: {self.helper_path}")
            return

        hand, _ = self.get_state()

        if low.startswith("fl"):
            arg_raw = cmd[2:].strip()
            if not arg_raw:
                self.set_latest("fl 用法示例：fl 3s / fl 3索 / fl 1饼")
                return
            
            if not hand:
                self.set_latest("[提示] 当前还没有抓到牌串，稍后再试。")
                return
            
            add = normalize_tile_spec(arg_raw)
            if not add:
                self.set_latest("fl 参数无法解析。示例：fl 3索 / fl 1饼")
                return
            
            expr = f"{hand}+{add}"
            self.set_latest(f"[running] {expr}")
            self._run_helper_async(expr)
            return

        if low.startswith("h"):
            expr = cmd[1:].strip()
            if not expr:
                self.set_latest("h 用法示例：h 234688m34s#6666p+3m")
                return
            
            self.set_latest(f"[running] {expr}")
            self._run_helper_async(expr)
            return

        if not any(ch.isdigit() for ch in cmd):
            self.set_latest("未识别命令。请输入包含数字的表达式或使用命令（d/dc/fl/h）")
            return

        self.set_latest(f"[running] {cmd}")
        self._run_helper_async(cmd)

    def loop(self):
        self.ent.focus_set()
        self.root.mainloop()


def main():
    ap = argparse.ArgumentParser(description="麻将实时分析管道")
    ap.add_argument("--name", default="Star.exe", help="进程名")
    ap.add_argument("--out", default="./bins", help="bin输出目录")
    ap.add_argument("--iface", default=None, help="抓包接口")
    ap.add_argument("--poll", type=float, default=0.3, help="端口轮询间隔")
    ap.add_argument("--udp", action="store_true", help="启用UDP")
    ap.add_argument("--no-external-only", action="store_true", help="抓取内网流量")
    ap.add_argument("--no-decompress", action="store_true", help="禁用zstd解压")
    ap.add_argument("--pb-no-zstd", action="store_true", help="禁用解析zstd")
    ap.add_argument("--pb-max-offset", type=int, default=512, help="protobuf偏移探测")
    ap.add_argument("--helper", default=None, help="mahjong-helper路径")
    ap.add_argument("--no-topmost-ui", action="store_true", help="不置顶GUI")
    ap.add_argument("--new-round-threshold", type=int, default=5, help="新局判定阈值")
    ap.add_argument("--keep-bins", action="store_true", help="保留抓包文件")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    helper_path = Path(args.helper).expanduser().resolve() if args.helper else (here / "mahjong-helper.exe")
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ui = GUI(helper_path=helper_path, topmost=(not args.no_topmost_ui))

    last_state = None
    last_compact = ""
    last_ts = 0.0
    last_all_tiles = None

    def flatten_all_tiles(cards, melds):
        flat = list(cards)
        for m in melds:
            flat.extend(list(m))
        return tuple(flat)

    def on_bin(info: Dict[str, Any]):
        nonlocal last_state, last_compact, last_ts, last_all_tiles
        
        fn = info.get("file")
        if not fn:
            return
        
        p = out_dir / fn
        for _ in range(3):
            if p.exists() and p.stat().st_size > 0:
                break
            time.sleep(0.01)

        try:
            parsed = parse_pb_bin(str(p), max_offset=args.pb_max_offset, allow_zstd=not args.pb_no_zstd)
        except Exception:
            return

        st = extract_hand(parsed)
        if not st:
            return
        
        if last_state == st:
            return

        compact = render_compact(st[0], st[1])
        ui.set_hand(compact)

        if compact == last_compact and time.time() - last_ts < 0.05:
            return

        last_state = st
        last_compact = compact
        last_ts = time.time()

        curr_all = flatten_all_tiles(st[0], st[1])
        if last_all_tiles is not None:
            changed = multiset_change_count(last_all_tiles, curr_all)
            if changed >= args.new_round_threshold:
                ui.clear_dora()
        last_all_tiles = curr_all

        t_total = total_tiles(st[0], st[1])
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        _, dora = ui.get_state()

        if t_total == 14:
            if not ui.helper_path.exists():
                ui.post_latest(f"[{ts}] [helper] 未找到: {ui.helper_path}")
                return
            
            out = run_helper(ui.helper_path, compact, dora_spec=(dora or None))
            ui.post_latest(f"[{ts}] AUTO\n> {ui.helper_path.name} {'-d='+dora if dora else ''} {compact}\n\n{out}")
        else:
            ui.post_latest(f"[{ts}] {compact}\n（合计 {t_total} 张，未触发自动分析）")

    cap = PacketCapture(
        interface=args.iface,
        process_name=args.name,
        output_dir=str(out_dir),
        poll_interval=args.poll,
        include_udp=bool(args.udp),
        external_only=not args.no_external_only,
        auto_decompress=not args.no_decompress,
    )
    
    cap.start(callback=on_bin)

    try:
        ui.loop()
    finally:
        cap.stop()
        
        # 清理抓包文件
        if not args.keep_bins:
            try:
                if out_dir.exists():
                    shutil.rmtree(out_dir)
                    print(f"\n[清理] 已删除抓包目录: {out_dir}")
            except Exception as e:
                print(f"\n[清理] 删除失败: {e}")
        else:
            print(f"\n[保留] 抓包文件保存在: {out_dir}")


if __name__ == "__main__":
    main()
