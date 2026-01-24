# Copyright (c) 2026 yuzeis
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import argparse
import os
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Callable, Tuple, Any, Set, List

import psutil
from scapy.all import sniff, get_if_list, IP, IPv6, TCP, UDP

# zstd解压支持
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False
    zstd = None


def ts_ms() -> str:
    """生成精确到毫秒的时间戳"""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


# ===== 网络接口工具函数 =====

def get_network_interfaces() -> List[Dict]:
    """
    获取可用的网络接口
    
    Returns:
        包含接口信息的字典列表，每个字典包含：
        - name: 接口名称
        - scapy_name: Scapy使用的接口名
        - addresses: IPv4地址列表
    """
    interfaces = []

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        scapy_ifaces = get_if_list()

        for name, addrs in net_if_addrs.items():
            # 跳过虚拟接口
            if name.startswith(("vEthernet", "VMware", "VirtualBox")):
                continue

            # 检查接口是否启用
            stats = net_if_stats.get(name)
            if stats and not stats.isup:
                continue

            # 收集IPv4地址
            ipv4_list = [addr.address for addr in addrs if addr.family == socket.AF_INET]
            if not ipv4_list:
                continue

            # 匹配Scapy接口名
            scapy_name = next(
                (si for si in scapy_ifaces if name.lower() in si.lower() or si.lower() in name.lower()),
                name
            )

            interfaces.append({
                "name": name,
                "scapy_name": scapy_name,
                "addresses": ipv4_list,
            })

    except Exception as e:
        print(f"[!] 获取网络接口失败: {e}")

    return interfaces


def _get_default_local_ipv4() -> Optional[str]:
    """通过UDP连接推断系统默认出口IPv4（不会真正发包）"""
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
    自动选择最可能可用的网络接口
    
    优先级：
    1. 仅有一个接口时直接选择
    2. 匹配默认出口IPv4对应的接口
    3. 回退选择第一个接口
    """
    if not interfaces:
        raise RuntimeError("未找到可用的网络接口")

    if len(interfaces) == 1:
        return 0

    default_ip = _get_default_local_ipv4()
    if default_ip:
        for i, iface in enumerate(interfaces):
            if default_ip in iface.get("addresses", []):
                return i

    return 0


def select_network_interface(interfaces: List[Dict]) -> int:
    """交互式选择网络接口"""
    if not interfaces:
        raise RuntimeError("未找到可用的网络接口")

    print("\n可用的网络接口:\n")
    for i, iface in enumerate(interfaces):
        addrs = ", ".join(iface["addresses"])
        print(f"  {i:2d}. {iface['name']}")
        print(f"      IPv4: {addrs}")
        print(f"      Scapy: {iface['scapy_name']}\n")

    while True:
        try:
            choice = input("请输入要使用的网络接口编号 (直接回车自动选择): ").strip()
            if not choice:
                return auto_select_network_interface(interfaces)
            
            index = int(choice)
            if 0 <= index < len(interfaces):
                return index
            print("[!] 接口编号超出范围")
        except ValueError:
            print("[!] 请输入有效的数字")
        except KeyboardInterrupt:
            print("\n[!] 用户取消选择")
            raise


# ===== IP过滤函数 =====

def is_private_or_loopback_ipv4(ip: str) -> bool:
    """判断是否为私有或回环地址"""
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
    """外网过滤：只要任一端是公网地址，就认为是外网相关"""
    if IP in pkt:
        return (not is_private_or_loopback_ipv4(pkt[IP].src)) or \
               (not is_private_or_loopback_ipv4(pkt[IP].dst))
    if IPv6 in pkt:
        return True
    return False


FlowKey = Tuple[str, int, str, int, int]  # (src_ip, src_port, dst_ip, dst_port, proto)


@dataclass
class DirReasm:
    """单向流重组数据"""
    next_seq: int = -1
    cache: Dict[int, bytes] = field(default_factory=dict)
    data: bytes = b""
    last_seen: float = 0.0


@dataclass
class TcpFlow:
    """TCP流状态"""
    forward: DirReasm = field(default_factory=DirReasm)
    reverse: DirReasm = field(default_factory=DirReasm)
    identified: bool = False


class PacketCapture:
    """
    网络包捕获器 - 输出独立bin文件
    支持zstd自动解压和大小过滤
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

        os.makedirs(output_dir, exist_ok=True)

        self.is_running = False
        self.callback: Optional[Callable[[Dict[str, Any]], None]] = None

        self._lock = threading.Lock()
        self._flows: Dict[FlowKey, TcpFlow] = {}

        self._pid: Optional[int] = None
        self._tcp_ports: Set[int] = set()
        self._udp_ports: Set[int] = set()

        # zstd解压器
        self._zstd_dctx = zstd.ZstdDecompressor() if HAS_ZSTD else None

        # 包计数器
        self._packet_counter = 0
        self._counter_lock = threading.Lock()

        # 统计数据
        self.stats = defaultdict(int)

    # -------------------- PID/端口追踪 --------------------

    @staticmethod
    def _find_pids_by_name(name: str) -> List[int]:
        """根据进程名查找PID"""
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
        """选择最新创建的进程"""
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
        """获取进程占用的TCP和UDP端口"""
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
        """端口更新循环"""
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
                self._pid = pid
                self._tcp_ports = tcp
                self._udp_ports = udp

            time.sleep(self.poll_interval)

    # -------------------- 启停 --------------------

    def start(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        """启动抓包"""
        self.callback = callback
        self.is_running = True
        threading.Thread(target=self._port_update_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def stop(self) -> None:
        """停止抓包"""
        self.is_running = False

    # -------------------- 抓包与过滤 --------------------

    def _sniff_loop(self) -> None:
        """抓包循环"""
        bpf = self.bpf_extra if self.bpf_extra else None

        def lfilter(pkt):
            if not (TCP in pkt or (self.include_udp and UDP in pkt)):
                return False
            
            if self.external_only and not external_only_packet(pkt):
                return False

            with self._lock:
                tcp_ports = set(self._tcp_ports)
                udp_ports = set(self._udp_ports)

            if TCP in pkt:
                return pkt[TCP].sport in tcp_ports or pkt[TCP].dport in tcp_ports
            
            if UDP in pkt:
                return pkt[UDP].sport in udp_ports or pkt[UDP].dport in udp_ports

            return False

        def prn(pkt):
            try:
                self._process_packet(pkt)
            except Exception:
                pass

        try:
            sniff(
                iface=self.interface,
                prn=prn,
                store=False,
                filter=bpf,
                lfilter=lfilter,
                stop_filter=lambda _: not self.is_running,
            )
        except Exception:
            pass

    def _get_next_packet_number(self) -> int:
        """获取下一个包编号（线程安全）"""
        with self._counter_lock:
            self._packet_counter += 1
            return self._packet_counter

    def _try_decompress_zstd(self, data: bytes) -> Tuple[bytes, bool]:
        """
        尝试解压zstd数据
        返回: (数据, 是否解压成功)
        """
        if not self.auto_decompress or not self._zstd_dctx:
            return data, False
        
        # zstd魔术字节: 0x28 0xB5 0x2F 0xFD
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
        写入单个bin文件
        返回文件名
        """
        # 尝试解压
        final_data, was_decompressed = self._try_decompress_zstd(payload)
        
        if was_decompressed:
            self.stats["decompressed_count"] += 1
        
        # 生成文件名
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

    # -------------------- 核心处理 --------------------

    def _process_packet(self, pkt) -> None:
        """处理单个数据包"""
        if not self.is_running:
            return

        self.stats["seen_total"] += 1

        # 取IP信息
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        # UDP处理
        if UDP in pkt and self.include_udp:
            self.stats["seen_udp"] += 1
            payload = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
            
            if len(payload) < self.min_size:
                self.stats["dropped_too_small"] += 1
                return
            
            self.stats["udp_payload_bytes"] += len(payload)
            
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

        # TCP处理
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
                })

    # -------------------- 清理线程 --------------------

    def _cleanup_loop(self) -> None:
        """清理超时流"""
        while self.is_running:
            time.sleep(5)
            now = time.time()
            
            with self._lock:
                dead = [
                    k for k, f in self._flows.items()
                    if max(f.forward.last_seen, f.reverse.last_seen) 
                    and (now - max(f.forward.last_seen, f.reverse.last_seen) > self.FRAGMENT_TIMEOUT)
                ]
                for k in dead:
                    self._flows.pop(k, None)


# -------------------- CLI --------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="网络包捕获器 - 二进制输出，自动接口选择")
    ap.add_argument("--list-ifaces", action="store_true", help="列出网络接口并退出")
    ap.add_argument("--iface", default=None, help="接口名称（未指定则自动选择）")
    ap.add_argument("--interactive", action="store_true", help="交互式选择接口")
    ap.add_argument("--name", required=False, default="", help="进程名，如 Star.exe")
    ap.add_argument("--out", default="", help="bin文件输出目录（默认: ./tcp_bins）")
    ap.add_argument("--min-size", type=int, default=0, help="最小包大小（字节）")
    ap.add_argument("--poll", type=float, default=0.3, help="端口轮询间隔（秒）")
    ap.add_argument("--no-external-only", action="store_true", help="也捕获私有/回环流量")
    ap.add_argument("--no-udp", action="store_true", help="不捕获UDP")
    ap.add_argument("--no-decompress", action="store_true", help="禁用zstd自动解压")
    args = ap.parse_args()

    # 获取网络接口列表
    interfaces = get_network_interfaces()
    
    if args.list_ifaces:
        if not interfaces:
            print("[!] 未找到可用的网络接口")
            return 1
        
        print("\n可用的网络接口:\n")
        for i, iface in enumerate(interfaces):
            addrs = ", ".join(iface["addresses"])
            print(f"  {i:2d}. {iface['name']}")
            print(f"      IPv4: {addrs}")
            print(f"      Scapy: {iface['scapy_name']}\n")
        return 0

    if not args.name:
        print("[!] 需要 --name 参数（进程名，如 Star.exe）")
        return 2

    # 选择网络接口
    if args.iface:
        iface = args.iface
        print(f"[+] 使用指定接口: {iface}")
    else:
        if not interfaces:
            print("[!] 未找到可用的网络接口")
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
        print(f"[+] 自动选择接口: {selected['name']} ({', '.join(selected['addresses'])})")
        print(f"[+] Scapy接口名: {iface}")

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
              f"{info.get('len')} bytes | {info.get('file')}")

    print("\n=== PacketCapture - 二进制输出 ===")
    print(f"进程         : {args.name}")
    print(f"接口         : {iface}")
    print(f"仅外网       : {not args.no_external_only}")
    print(f"UDP          : {not args.no_udp}")
    print(f"最小包大小   : {args.min_size} bytes")
    print(f"自动解压     : {not args.no_decompress}")
    print(f"输出目录     : {out}")
    print(f"ZSTD支持     : {'YES' if HAS_ZSTD else 'NO (需安装 zstandard)'}")
    print("\n按 Ctrl+C 停止。\n")

    cap.start(callback=cb)

    try:
        while True:
            time.sleep(5)
            s = cap.stats
            print(f"[统计] pid={cap._pid} tcp端口={len(cap._tcp_ports)} udp端口={len(cap._udp_ports)} | "
                  f"总包={s['seen_total']} tcp={s['seen_tcp']} udp={s['seen_udp']} "
                  f"输出={s['written_bins']} tcp字节={s['tcp_payload_bytes']} "
                  f"过小丢弃={s['dropped_too_small']} 解压={s['decompressed_count']}")
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
        print(f"\n[+] 二进制文件已保存至: {out}")
        print(f"[+] 总文件数: {cap.stats['written_bins']}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
