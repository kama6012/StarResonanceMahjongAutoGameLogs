# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import argparse
import os
import socket
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Callable, Tuple, Any, Set, List

import psutil
from scapy.all import conf, sniff, get_if_list, IP, IPv6, TCP, UDP

# zstd展開のサポート
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False
    zstd = None


def ts_ms() -> str:
    """ミリ秒まで含むタイムスタンプを生成する。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


# ===== ネットワークインターフェース補助関数 =====

def get_network_interfaces() -> List[Dict]:
    """
    利用可能なネットワークインターフェースを取得する。
    
    戻り値:
        インターフェース情報を含む辞書のリスト。各辞書には次を含む：
        - name：インターフェース名
        - scapy_name：Scapyが使用するインターフェース名
        - addresses：IPv4アドレスのリスト
    """
    interfaces = []

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        scapy_ifaces = get_if_list()

        for name, addrs in net_if_addrs.items():
            # 仮想インターフェースを除外
            if name.startswith(("vEthernet", "VMware", "VirtualBox")):
                continue

            # インターフェースが有効か確認
            stats = net_if_stats.get(name)
            if stats and not stats.isup:
                continue

            # IPv4アドレスを収集
            ipv4_list = [addr.address for addr in addrs if addr.family == socket.AF_INET]
            if not ipv4_list:
                continue

            # WindowsではNpcapデバイス名とpsutilの表示名が一致しないため、
            # ScapyのインターフェースオブジェクトをIPまたは表示名で対応付ける。
            scapy_name = name
            for scapy_iface in conf.ifaces.values():
                iface_name = str(getattr(scapy_iface, "name", ""))
                iface_ip = str(getattr(scapy_iface, "ip", ""))
                if iface_ip in ipv4_list or iface_name.casefold() == name.casefold():
                    scapy_name = str(scapy_iface)
                    break
            else:
                scapy_name = next(
                    (si for si in scapy_ifaces if name.casefold() in si.casefold()),
                    name,
                )

            interfaces.append({
                "name": name,
                "scapy_name": scapy_name,
                "addresses": ipv4_list,
            })

    except Exception as e:
        print(f"[!] ネットワークインターフェースの取得に失敗しました：{e}")

    return interfaces


def _get_default_local_ipv4() -> Optional[str]:
    """UDP接続からシステムのデフォルト出口IPv4を推定する（実際には送信しない）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def auto_select_network_interface(interfaces: List[Dict]) -> int:
    """
    利用可能性が最も高いネットワークインターフェースを自動選択する。
    
    優先順位：
    1. インターフェースが1つだけなら直接選択
    2. デフォルト出口IPv4に対応するインターフェースを選択
    3. 最初のインターフェースにフォールバック
    """
    if not interfaces:
        raise RuntimeError("利用可能なネットワークインターフェースが見つかりません")

    if len(interfaces) == 1:
        return 0

    default_ip = _get_default_local_ipv4()
    if default_ip:
        for i, iface in enumerate(interfaces):
            if default_ip in iface.get("addresses", []):
                return i

    return 0


def select_network_interface(interfaces: List[Dict]) -> int:
    """ネットワークインターフェースを対話的に選択する。"""
    if not interfaces:
        raise RuntimeError("利用可能なネットワークインターフェースが見つかりません")

    print("\n利用可能なネットワークインターフェース：\n")
    for i, iface in enumerate(interfaces):
        addrs = ", ".join(iface["addresses"])
        print(f"  {i:2d}. {iface['name']}")
        print(f"      IPv4：{addrs}")
        print(f"      Scapy：{iface['scapy_name']}\n")

    while True:
        try:
            choice = input("使用するインターフェース番号を入力してください（空欄で自動選択）：").strip()
            if not choice:
                return auto_select_network_interface(interfaces)
            
            index = int(choice)
            if 0 <= index < len(interfaces):
                return index
            print("[!] インターフェース番号が範囲外です")
        except ValueError:
            print("[!] 有効な数字を入力してください")
        except KeyboardInterrupt:
            print("\n[!] ユーザーが選択をキャンセルしました")
            raise


# ===== IPフィルター関数 =====

def is_private_or_loopback_ipv4(ip: str) -> bool:
    """プライベートアドレスまたはループバックアドレスか判定する。"""
    if ip.startswith(("127.", "10.", "192.168.")):
        return True
    
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    
    return False


def external_only_packet(pkt) -> bool:
    """外部通信をフィルターする。一方の端でもグローバルアドレスなら対象とする。"""
    if IP in pkt:
        return (not is_private_or_loopback_ipv4(pkt[IP].src)) or \
               (not is_private_or_loopback_ipv4(pkt[IP].dst))
    if IPv6 in pkt:
        return True
    return False


@dataclass(frozen=True)
class CaptureStatus:
    """外部コンポーネントへ公開する捕捉器の読み取り専用状態。"""
    interface: Optional[str]
    pid: Optional[int]
    tcp_ports: Tuple[int, ...]
    udp_ports: Tuple[int, ...]
    is_running: bool
    last_error: Optional[str]


class PacketCapture:
    """
    ネットワークパケット捕捉器。独立したbinファイルへ出力する。
    zstd自動展開とサイズフィルターに対応する。
    """

    MAX_PACKET_SIZE = 0x0FFFFF
    FRAGMENT_TIMEOUT = 30

    def __init__(
        self,
        interface: Optional[str],
        process_name: str,
        output_dir: str,
        min_size: int = 0,
        poll_interval: float = 0.3,
        external_only: bool = True,
        include_udp: bool = True,
        identify_signature: bytes = b"\x00\x63\x33\x53\x42\x00",
        bpf_extra: Optional[str] = None,
        auto_decompress: bool = True,
        tcp_watch_ports: Optional[Set[int]] = None,
        write_files: bool = True,
    ):
        self.interface = interface
        self.process_name = process_name
        self.output_dir = output_dir
        self.min_size = min_size
        self.poll_interval = poll_interval
        self.external_only = external_only
        self.include_udp = include_udp
        self.identify_signature = identify_signature
        self.bpf_extra = bpf_extra
        self.auto_decompress = auto_decompress
        self.tcp_watch_ports = set(tcp_watch_ports or ())
        self.write_files = bool(write_files)

        os.makedirs(output_dir, exist_ok=True)

        self.is_running = False
        self.callback: Optional[Callable[[Dict[str, Any]], None]] = None

        self._lock = threading.Lock()
        self._pid: Optional[int] = None
        self._tcp_ports: Set[int] = set()
        self._udp_ports: Set[int] = set()

        # zstd展開器
        self._zstd_dctx = zstd.ZstdDecompressor() if HAS_ZSTD else None

        # パケットカウンター
        self._packet_counter = 0
        self._counter_lock = threading.Lock()

        # 統計データ
        self.stats = defaultdict(int)
        self.last_error: Optional[str] = None
        self.sniff_started = threading.Event()

    # -------------------- PID・ポート追跡 --------------------

    @staticmethod
    def _find_pids_by_name(name: str) -> List[int]:
        """プロセス名からPIDを検索する。"""
        n = name.lower().strip()
        pids = []
        
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pn = (p.info.get("name") or "").lower()
                pe = (p.info.get("exe") or "").lower()
                if n == pn or n in pn or (n and n in pe):
                    pids.append(p.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return sorted(set(pids))

    @staticmethod
    def _choose_pid(pids: List[int]) -> Optional[int]:
        """最も新しく作成されたプロセスを選択する。"""
        best = None
        best_ctime = -1.0
        
        for pid in pids:
            try:
                ctime = psutil.Process(pid).create_time()
                if ctime > best_ctime:
                    best_ctime = ctime
                    best = pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return best

    @staticmethod
    def _ports_for_pid(pid: int) -> Tuple[Set[int], Set[int]]:
        """プロセスが使用しているTCP・UDPポートを取得する。"""
        tcp_ports: Set[int] = set()
        udp_ports: Set[int] = set()
        
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.pid != pid or not c.laddr:
                    continue
                
                lport = c.laddr.port
                if c.type == socket.SOCK_STREAM:
                    tcp_ports.add(lport)
                elif c.type == socket.SOCK_DGRAM:
                    udp_ports.add(lport)
        except (psutil.AccessDenied, OSError):
            pass
        
        return tcp_ports, udp_ports

    def _port_update_loop(self) -> None:
        """ポート更新ループ。"""
        while self.is_running:
            pids = self._find_pids_by_name(self.process_name)
            pid = self._choose_pid(pids) if pids else None

            if pid is None:
                with self._lock:
                    self._pid = None
                    self._tcp_ports.clear()
                    self._udp_ports.clear()
                time.sleep(self.poll_interval)
                continue

            tcp, udp = self._ports_for_pid(pid)

            with self._lock:
                if self._pid != pid:
                    # プロセスが再起動した場合だけ古い接続を捨てる。
                    self._tcp_ports.clear()
                    self._udp_ports.clear()
                self._pid = pid
                # psutil.net_connections()はWindows上で一時的に空や不完全な
                # 結果を返すことがある。稼働中の同一PIDについて、既知の
                # ポートを一度の揺らぎで失わないよう累積する。
                self._tcp_ports.update(tcp)
                self._udp_ports.update(udp)

            time.sleep(self.poll_interval)

    def _refresh_process_ports(self) -> None:
        """対象PIDとポートを同期的に1回更新する。"""
        pids = self._find_pids_by_name(self.process_name)
        pid = self._choose_pid(pids) if pids else None
        tcp, udp = self._ports_for_pid(pid) if pid is not None else (set(), set())
        with self._lock:
            self._pid = pid
            self._tcp_ports = tcp
            self._udp_ports = udp

    # -------------------- 起動・停止 --------------------

    def start(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        """パケット捕捉を開始する。"""
        if not self.interface:
            interfaces = get_network_interfaces()
            if not interfaces:
                raise RuntimeError("捕捉可能なネットワークインターフェースが見つかりません")
            self.interface = interfaces[auto_select_network_interface(interfaces)]["scapy_name"]

        self.callback = callback
        self.last_error = None
        self.sniff_started.clear()
        self._refresh_process_ports()
        self.is_running = True
        threading.Thread(target=self._port_update_loop, daemon=True).start()
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def stop(self) -> None:
        """パケット捕捉を停止する。"""
        self.is_running = False

    def status_snapshot(self) -> CaptureStatus:
        """内部lockや可変setを公開せず、現在状態のスナップショットを返す。"""
        with self._lock:
            return CaptureStatus(
                self.interface,
                self._pid,
                tuple(sorted(self._tcp_ports)),
                tuple(sorted(self._udp_ports)),
                self.is_running,
                self.last_error,
            )

    def local_tcp_ports(self) -> Set[int]:
        with self._lock:
            return set(self._tcp_ports)

    # -------------------- パケット捕捉とフィルター --------------------

    def _sniff_loop(self) -> None:
        """パケット捕捉ループ。"""
        bpf = self.bpf_extra if self.bpf_extra else None

        def lfilter(pkt):
            if not (TCP in pkt or (self.include_udp and UDP in pkt)):
                return False
            
            if self.external_only and not external_only_packet(pkt):
                return False

            with self._lock:
                tcp_ports = set(self._tcp_ports) | self.tcp_watch_ports
                udp_ports = set(self._udp_ports)

            if TCP in pkt:
                return pkt[TCP].sport in tcp_ports or pkt[TCP].dport in tcp_ports
            
            if UDP in pkt:
                return pkt[UDP].sport in udp_ports or pkt[UDP].dport in udp_ports

            return False

        def prn(pkt):
            try:
                self._process_packet(pkt)
            except Exception as exc:
                self.stats["packet_errors"] += 1
                self.last_error = f"packet callback {type(exc).__name__}: {exc}"
                print(f"[パケット処理エラー] {self.last_error}", file=sys.stderr)

        try:
            self.sniff_started.set()
            sniff(
                iface=self.interface,
                prn=prn,
                store=False,
                filter=bpf,
                lfilter=lfilter,
                stop_filter=lambda _: not self.is_running,
            )
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self.stats["sniff_errors"] += 1
            self.is_running = False
            print(f"[捕捉エラー] {self.last_error}", file=sys.stderr)

    def _get_next_packet_number(self) -> int:
        """次のパケット番号を取得する（スレッドセーフ）。"""
        with self._counter_lock:
            self._packet_counter += 1
            return self._packet_counter

    def _try_decompress_zstd(self, data: bytes) -> Tuple[bytes, bool]:
        """
        zstdデータの展開を試みる。
        戻り値：(データ、展開に成功したかどうか)
        """
        if not self.auto_decompress or not self._zstd_dctx:
            return data, False
        
        # zstdマジックバイト：0x28 0xB5 0x2F 0xFD
        if len(data) >= 4 and data[:4] == b'\x28\xB5\x2F\xFD':
            try:
                decompressed = self._zstd_dctx.decompress(data, max_output_size=16 * 1024 * 1024)
                return decompressed, True
            except Exception:
                pass
        
        return data, False

    def _write_bin_file(self, payload: bytes, src_ip: str, src_port: int, 
                        dst_ip: str, dst_port: int, proto: str) -> str:
        """
        1つのbinファイルを書き込む。
        ファイル名を返す。
        """
        # 展開を試行
        final_data, was_decompressed = self._try_decompress_zstd(payload)
        
        if was_decompressed:
            self.stats["decompressed_count"] += 1
        
        # ファイル名を生成
        pkt_num = self._get_next_packet_number()
        timestamp = ts_ms()
        comp_mark = "_zstd" if was_decompressed else ""
        
        filename = (
            f"{timestamp}_{pkt_num:08d}_{proto}_"
            f"{src_ip.replace(':', '-')}_{src_port}_to_"
            f"{dst_ip.replace(':', '-')}_{dst_port}"
            f"{comp_mark}.bin"
        )
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'wb') as f:
            f.write(final_data)
        
        self.stats["written_bins"] += 1
        return filename

    # -------------------- 中核処理 --------------------

    def _process_packet(self, pkt) -> None:
        """1つのパケットを処理する。"""
        if not self.is_running:
            return

        self.stats["seen_total"] += 1

        # IP情報を取得
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        # UDP処理
        if UDP in pkt and self.include_udp:
            self.stats["seen_udp"] += 1
            payload = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
            
            if len(payload) < self.min_size:
                self.stats["dropped_too_small"] += 1
                return
            
            self.stats["udp_payload_bytes"] += len(payload)
            
            filename = None
            if self.write_files:
                filename = self._write_bin_file(
                    payload,
                    src_ip, int(pkt[UDP].sport),
                    dst_ip, int(pkt[UDP].dport),
                    "UDP"
                )
            
            if self.callback:
                self.callback({
                    "kind": "UDP",
                    "src": f"{src_ip}:{int(pkt[UDP].sport)}",
                    "dst": f"{dst_ip}:{int(pkt[UDP].dport)}",
                    "len": len(payload),
                    "file": filename,
                })
            return

        # TCP処理
        if TCP in pkt:
            self.stats["seen_tcp"] += 1
            tcp = pkt[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b""
            
            if not payload:
                self.stats["dropped_no_payload"] += 1
                return
            
            if len(payload) < self.min_size:
                self.stats["dropped_too_small"] += 1
                return

            self.stats["tcp_payload_bytes"] += len(payload)
            self.stats["matched_by_ports"] += 1

            filename = None
            if self.write_files:
                filename = self._write_bin_file(
                    payload,
                    src_ip, int(tcp.sport),
                    dst_ip, int(tcp.dport),
                    "TCP"
                )
            
            if self.callback:
                self.callback({
                    "kind": "TCP",
                    "src": f"{src_ip}:{int(tcp.sport)}",
                    "dst": f"{dst_ip}:{int(tcp.dport)}",
                    "len": len(payload),
                    "file": filename,
                    # リアルタイムのストリーム復元用途。保存ファイルは従来どおり維持する。
                    "payload": payload,
                    "seq": int(tcp.seq),
                })

# -------------------- CLI --------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="ネットワークパケット捕捉器 - バイナリ出力、インターフェース自動選択")
    ap.add_argument("--list-ifaces", action="store_true", help="ネットワークインターフェースを一覧表示して終了")
    ap.add_argument("--iface", default=None, help="インターフェース名（未指定時は自動選択）")
    ap.add_argument("--interactive", action="store_true", help="インターフェースを対話的に選択")
    ap.add_argument("--name", required=False, default="", help="プロセス名（例：Star.exe）")
    ap.add_argument("--out", default="", help="binファイルの出力先（既定値：./tcp_bins）")
    ap.add_argument("--min-size", type=int, default=0, help="パケットの最小サイズ（バイト）")
    ap.add_argument("--poll", type=float, default=0.3, help="ポート確認間隔（秒）")
    ap.add_argument("--no-external-only", action="store_true", help="プライベート・ループバック通信も捕捉")
    ap.add_argument("--no-udp", action="store_true", help="UDPを捕捉しない")
    ap.add_argument("--no-decompress", action="store_true", help="zstd自動展開を無効化")
    args = ap.parse_args()

    # ネットワークインターフェース一覧を取得
    interfaces = get_network_interfaces()
    
    if args.list_ifaces:
        if not interfaces:
            print("[!] 利用可能なネットワークインターフェースが見つかりません")
            return 1
        
        print("\n利用可能なネットワークインターフェース：\n")
        for i, iface in enumerate(interfaces):
            addrs = ", ".join(iface["addresses"])
            print(f"  {i:2d}. {iface['name']}")
            print(f"      IPv4：{addrs}")
            print(f"      Scapy：{iface['scapy_name']}\n")
        return 0

    if not args.name:
        print("[!] --name引数が必要です（プロセス名。例：Star.exe）")
        return 2

    # ネットワークインターフェースを選択
    if args.iface:
        iface = args.iface
        print(f"[+] 指定インターフェースを使用：{iface}")
    else:
        if not interfaces:
            print("[!] 利用可能なネットワークインターフェースが見つかりません")
            return 1
        
        try:
            if args.interactive:
                index = select_network_interface(interfaces)
            else:
                index = auto_select_network_interface(interfaces)
        except (KeyboardInterrupt, RuntimeError) as e:
            print(f"[!] {e}")
            return 2
        
        selected = interfaces[index]
        iface = selected["scapy_name"]
        print(f"[+] インターフェースを自動選択：{selected['name']}（{', '.join(selected['addresses'])}）")
        print(f"[+] Scapyインターフェース名：{iface}")

    out = args.out.strip() or os.path.join(".", "tcp_bins")
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)

    cap = PacketCapture(
        interface=iface,
        process_name=args.name,
        output_dir=out,
        min_size=args.min_size,
        poll_interval=args.poll,
        external_only=not args.no_external_only,
        include_udp=not args.no_udp,
        auto_decompress=not args.no_decompress,
    )

    def cb(info: Dict[str, Any]):
        print(f"[{info.get('kind')}] {info.get('src')} -> {info.get('dst')} | "
              f"{info.get('len')} バイト | {info.get('file')}")

    print("\n=== PacketCapture - バイナリ出力 ===")
    print(f"プロセス       ：{args.name}")
    print(f"インターフェース：{iface}")
    print(f"外部通信のみ   ：{not args.no_external_only}")
    print(f"UDP           ：{not args.no_udp}")
    print(f"最小パケットサイズ：{args.min_size} バイト")
    print(f"自動展開       ：{not args.no_decompress}")
    print(f"出力先         ：{out}")
    print(f"ZSTDサポート  ：{'あり' if HAS_ZSTD else 'なし（zstandardのインストールが必要）'}")
    print("\nCtrl+Cで停止します。\n")

    cap.start(callback=cb)

    try:
        while True:
            time.sleep(5)
            s = cap.stats
            status = cap.status_snapshot()
            print(f"[統計] PID={status.pid} TCPポート={len(status.tcp_ports)} UDPポート={len(status.udp_ports)} | "
                  f"総パケット={s['seen_total']} TCP={s['seen_tcp']} UDP={s['seen_udp']} "
                  f"出力={s['written_bins']} TCPバイト={s['tcp_payload_bytes']} "
                  f"小さすぎて破棄={s['dropped_too_small']} 展開={s['decompressed_count']}")
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
        print(f"\n[+] バイナリファイルを保存しました：{out}")
        print(f"[+] ファイル総数：{cap.stats['written_bins']}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
