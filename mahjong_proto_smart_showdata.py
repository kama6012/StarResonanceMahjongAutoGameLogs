# Copyright (c) 2026 yuzeis
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import argparse
import base64
import binascii
import io
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ===== 通用protobuf解析 =====

def _is_printable_utf8(b: bytes) -> bool:
    """检查字节是否为可打印的UTF-8"""
    try:
        s = b.decode("utf-8")
        bad = sum(1 for ch in s if ord(ch) < 32 and ch not in "\t\n\r")
        return bad == 0
    except Exception:
        return False


def _try_decode_utf8(b: bytes) -> Optional[str]:
    """尝试UTF-8解码"""
    try:
        return b.decode("utf-8")
    except Exception:
        return None


def _looks_like_protobuf(b: bytes) -> bool:
    """启发式判断是否为protobuf（最终由解析成功与否决定）"""
    return bool(b) and b[0] != 0


def _parse_unknown_protobuf(data: bytes, *, max_depth: int = 3, _depth: int = 0, 
                            max_fields: int = 2000) -> dict:
    """
    无schema解析protobuf
    返回 dict: field -> list(values)
    """
    r = ProtoReader(data)
    out: dict = {}
    count = 0
    
    while not r.eof():
        if count >= max_fields:
            out["_truncated"] = True
            break
        
        pos = r.i
        try:
            field, wire, key_pos = r.read_key()
        except Exception as e:
            out["_parse_error"] = f"{e}"
            break
        
        count += 1
        
        try:
            if wire == 0:
                v = r.read_varint()
            elif wire == 1:
                v = r.read_fixed64()
            elif wire == 5:
                v = r.read_fixed32()
            elif wire == 2:
                ln = r.read_varint()
                b = r.read_bytes(ln)
                s = _try_decode_utf8(b) if _is_printable_utf8(b) else None
                
                if s is not None:
                    v = s
                elif _depth < max_depth and _looks_like_protobuf(b):
                    nested = _parse_unknown_protobuf(b, max_depth=max_depth, 
                                                    _depth=_depth + 1, max_fields=max_fields)
                    has_numeric_key = any(k.isdigit() for k in nested.keys())
                    
                    if has_numeric_key and "_parse_error" not in nested:
                        v = {"_as": "message", "value": nested, "_len": len(b)}
                    else:
                        v = {"_as": "base64", "value": base64.b64encode(b).decode("ascii"), "_len": len(b)}
                else:
                    v = {"_as": "base64", "value": base64.b64encode(b).decode("ascii"), "_len": len(b)}
            elif wire == 3:
                raw = r.skip_field(field, wire)
                v = {"_as": "group", "raw_hex": raw.hex()}
            elif wire == 4:
                out["_unexpected_end_group"] = True
                break
            else:
                raw = r.skip_field(field, wire)
                v = {"_as": "raw", "wire": wire, "raw_hex": raw.hex()}
        except Exception as e:
            v = {"_error": str(e), "wire": wire, "pos": pos}
        
        out.setdefault(str(field), []).append(v)
    
    return out


def _decode_showdata_bytes(b: bytes) -> dict:
    """解码MahjongPlayerShow.ShowData字段"""
    decoded = _parse_unknown_protobuf(b, max_depth=4) if b else {}
    return {
        "_as": "showdata",
        "_len": len(b),
        "raw_base64": base64.b64encode(b).decode("ascii"),
        "decoded": decoded,
    }


# ===== Zstd助手 =====

def maybe_zstd_decompress(data: bytes) -> Tuple[bytes, bool, str]:
    """
    尝试解压zstd帧数据
    支持无内容大小的帧（stream_reader）
    返回 (payload, is_zstd, note)
    """
    # zstd帧魔术字节: 28 B5 2F FD
    candidates = [0]
    for i in range(1, min(4096, len(data) - 4)):
        if data[i:i + 4] == b"\x28\xb5\x2f\xfd":
            candidates.append(i)
            break

    try:
        import zstandard as zstd
    except ImportError as e:
        return data, False, f"zstd模块不可用 ({e})"

    last_err: Optional[Exception] = None
    for off in candidates:
        try:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(data[off:])) as reader:
                out = reader.read()
            if out:
                return out, True, f"zstd流解压成功（偏移 {off}）"
        except Exception as e:
            last_err = e
            continue

    return data, False, f"未使用zstd ({last_err})" if last_err else "未使用zstd"


# ===== Protobuf wire reader =====

class ProtoDecodeError(Exception):
    """Protobuf解码错误"""
    pass


class ProtoReader:
    """Protobuf字节流读取器"""
    
    def __init__(self, data: bytes, start: int = 0, limit: Optional[int] = None):
        self.data = data
        self.i = start
        self.start = start
        self.limit = len(data) if limit is None else min(len(data), limit)

    def tell(self) -> int:
        return self.i

    def eof(self) -> bool:
        return self.i >= self.limit

    def _need(self, n: int):
        if self.i + n > self.limit:
            raise ProtoDecodeError(f"意外EOF need={n} at {self.i} limit={self.limit}")

    def read_u8(self) -> int:
        self._need(1)
        b = self.data[self.i]
        self.i += 1
        return b

    def read_varint(self, max_bits: int = 64) -> int:
        shift = 0
        result = 0
        while True:
            if shift >= max_bits:
                raise ProtoDecodeError(f"varint过长 at {self.i}")
            b = self.read_u8()
            result |= ((b & 0x7F) << shift)
            if (b & 0x80) == 0:
                return result
            shift += 7

    def read_fixed32(self) -> int:
        self._need(4)
        v = int.from_bytes(self.data[self.i:self.i + 4], "little", signed=False)
        self.i += 4
        return v

    def read_fixed64(self) -> int:
        self._need(8)
        v = int.from_bytes(self.data[self.i:self.i + 8], "little", signed=False)
        self.i += 8
        return v

    def read_bytes(self, n: int) -> bytes:
        self._need(n)
        b = self.data[self.i:self.i + n]
        self.i += n
        return b

    def read_key(self) -> Tuple[int, int, int]:
        """返回 (field, wire, key_pos)"""
        key_pos = self.i
        key = self.read_varint(32)
        wire = key & 0x7
        field = key >> 3
        return field, wire, key_pos

    def skip_field(self, field: int, wire: int) -> bytes:
        """跳过字段值字节（不包括key varint）"""
        if wire == 0:
            start = self.i
            _ = self.read_varint(64)
            return self.data[start:self.i]
        if wire == 1:
            start = self.i
            _ = self.read_fixed64()
            return self.data[start:self.i]
        if wire == 2:
            ln = self.read_varint(32)
            start = self.i
            _ = self.read_bytes(ln)
            return self.data[start:self.i]
        if wire == 3:
            # start-group: 消费直到匹配的end-group (wire=4)
            start = self.i
            depth = 1
            while not self.eof() and depth > 0:
                f2, w2, _kp = self.read_key()
                if w2 == 3:
                    depth += 1
                    _ = self.skip_field(f2, w2)
                elif w2 == 4:
                    depth -= 1
                    if depth == 0:
                        break
                else:
                    _ = self.skip_field(f2, w2)
            return self.data[start:self.i]
        if wire == 4:
            return b""
        if wire == 5:
            start = self.i
            _ = self.read_fixed32()
            return self.data[start:self.i]
        raise ProtoDecodeError(f"不支持的wire={wire}")


# ===== Schema系统 =====

@dataclass(frozen=True)
class FieldSpec:
    """字段规格"""
    name: str
    kind: str  # int32,int64,bool,string,bytes,repeated_int32,message,repeated_message
    msg: Optional[str] = None
    packed_ok: bool = False


Schema = Dict[int, FieldSpec]
SCHEMAS: Dict[str, Schema] = {}


def define_schema(msg: str, schema: Schema):
    """定义消息schema"""
    SCHEMAS[msg] = schema


# 已知消息定义
define_schema("Zproto.MahjongOpenMeld", {
    1: FieldSpec("MeldType", "int32"),
    2: FieldSpec("Cards", "repeated_int32", packed_ok=True),
    3: FieldSpec("Card", "int32"),
    4: FieldSpec("FromPlayerIndex", "int32"),
})

define_schema("Zproto.MahjongPlayerShow", {
    1: FieldSpec("PlayerId", "int64"),
    2: FieldSpec("PlayerIndex", "int32"),
    3: FieldSpec("Coin", "int32"),
    4: FieldSpec("SelfWind", "int32"),
    5: FieldSpec("Lizhi", "int32"),
    6: FieldSpec("DropCards", "repeated_int32", packed_ok=True),
    7: FieldSpec("OpenMelds", "repeated_message", msg="Zproto.MahjongOpenMeld"),
    8: FieldSpec("CardsLen", "int32"),
    9: FieldSpec("IsLastDraw", "bool"),
    10: FieldSpec("Cards", "repeated_int32", packed_ok=True),
    11: FieldSpec("Furtin", "int32"),
    12: FieldSpec("ShowData", "bytes"),
})

define_schema("Zproto.MahjongSyncMessage", {
    1: FieldSpec("DealerIndex", "int32"),
    2: FieldSpec("Wind", "int32"),
    3: FieldSpec("WaitTime", "int32"),
    4: FieldSpec("Doras", "repeated_int32", packed_ok=True),
    5: FieldSpec("Operations", "repeated_message", msg="Zproto.MahjongOperation"),
    6: FieldSpec("CurrentIndex", "int32"),
    7: FieldSpec("CardIndex", "int32"),
    8: FieldSpec("Players", "repeated_message", msg="Zproto.MahjongPlayerShow"),
    9: FieldSpec("PlayerSelf", "message", msg="Zproto.MahjongPlayerSelf"),
    10: FieldSpec("LizhiCount", "int32"),
    11: FieldSpec("HonbaCounter", "int32"),
    12: FieldSpec("ZhuangCounter", "int32"),
    13: FieldSpec("ForceRefresh", "bool"),
    14: FieldSpec("MahjongTableGuid", "string"),
})

define_schema("Zproto.MahjongSyncOpMessage", {
    1: FieldSpec("Operation", "message", msg="Zproto.MahjongOperation"),
    2: FieldSpec("Doras", "repeated_int32", packed_ok=True),
    3: FieldSpec("CurrentIndex", "int32"),
    4: FieldSpec("LizhiCount", "int32"),
    5: FieldSpec("HonbaCounter", "int32"),
    6: FieldSpec("CardIndex", "int32"),
    7: FieldSpec("Players", "repeated_message", msg="Zproto.MahjongPlayerShow"),
    8: FieldSpec("PlayerSelf", "message", msg="Zproto.MahjongPlayerSelf"),
})

# 未知内部消息：保持空schema
define_schema("Zproto.MahjongOperation", {})
define_schema("Zproto.MahjongPlayerSelf", {})


# ===== 助手函数 =====

def _try_utf8(b: bytes) -> Optional[str]:
    """尝试UTF-8解码"""
    try:
        s = b.decode("utf-8")
        bad = sum(1 for ch in s if ord(ch) < 0x20 and ch not in "\r\n\t")
        return None if bad > 0 else s
    except Exception:
        return None


def _hex_preview(b: bytes, n: int = 64) -> str:
    """生成hex预览"""
    h = binascii.hexlify(b[:n]).decode("ascii")
    return h + ("..." if len(b) > n else "")


# ===== 智能解码器 =====

@dataclass
class DecodeResult:
    """解码结果"""
    obj: Dict[str, Any]
    fatal: bool
    unknown_count: int
    known_count: int
    end_pos: int


class ProtobufSmartDecoder:
    """智能Protobuf解码器"""
    
    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth

    def decode_as(self, msg_type: str, data: bytes, start: int = 0, 
                  depth: int = 0, limit: Optional[int] = None) -> DecodeResult:
        """按指定类型解码"""
        schema = SCHEMAS.get(msg_type, {})
        r = ProtoReader(data, start=start, limit=limit)
        out: Dict[str, Any] = {
            "_type": msg_type, 
            "_unknown": [], 
            "_fatal": False, 
            "_start": start
        }
        known = 0
        unknown = 0

        # 预创建repeated字段的列表
        for fs in schema.values():
            if fs.kind in ("repeated_int32", "repeated_message"):
                out.setdefault(fs.name, [])

        while not r.eof():
            pos_before = r.tell()
            try:
                field, wire, key_pos = r.read_key()
            except ProtoDecodeError as e:
                out["_unknown"].append({
                    "field": -1, "wire": -1, "pos": r.tell(), 
                    "raw": "", "note": f"key解码错误: {e}"
                })
                out["_fatal"] = True
                break

            # 非法字段号0
            if field == 0:
                out["_unknown"].append({
                    "field": 0, "wire": wire, "pos": key_pos, 
                    "raw": data[key_pos:key_pos + 1].hex(), 
                    "note": "非法字段号0（错误偏移/非protobuf起点）"
                })
                out["_fatal"] = True
                break

            # 顶层end-group -> 错误偏移
            if wire == 4:
                out["_unknown"].append({
                    "field": field, "wire": 4, "pos": key_pos, 
                    "raw": "", "note": "意外end-group（错误偏移/损坏）"
                })
                out["_fatal"] = True
                break

            fs = schema.get(field)
            try:
                if fs is None:
                    raw = r.skip_field(field, wire)
                    unknown += 1
                    out["_unknown"].append({
                        "field": field, "wire": wire, "pos": key_pos, 
                        "raw": _hex_preview(raw)
                    })
                    continue

                # 已知字段
                if fs.kind in ("int32", "int64"):
                    if wire != 0:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), 
                            "note": f"wire不匹配，期望varint for {fs.kind}"
                        })
                        out["_fatal"] = True
                        break
                    out[fs.name] = int(r.read_varint(64))
                    known += 1

                elif fs.kind == "bool":
                    if wire != 0:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), "note": "wire不匹配，期望varint for bool"
                        })
                        out["_fatal"] = True
                        break
                    out[fs.name] = bool(r.read_varint(64) != 0)
                    known += 1

                elif fs.kind == "string":
                    if wire != 2:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), "note": "wire不匹配，期望len-delimited for string"
                        })
                        out["_fatal"] = True
                        break
                    ln = r.read_varint(32)
                    b = r.read_bytes(ln)
                    s = _try_utf8(b)
                    out[fs.name] = s if s is not None else {
                        "_as": "base64", 
                        "value": base64.b64encode(b).decode("ascii"), 
                        "_len": len(b)
                    }
                    known += 1

                elif fs.kind == "bytes":
                    if wire != 2:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), "note": "wire不匹配，期望len-delimited for bytes"
                        })
                        out["_fatal"] = True
                        break
                    ln = r.read_varint(32)
                    b = r.read_bytes(ln)
                    
                    if fs.name == "ShowData":
                        out[fs.name] = _decode_showdata_bytes(b)
                    else:
                        s = _try_utf8(b)
                        if s is not None and len(s) <= 4096:
                            out[fs.name] = {"_as": "utf8", "value": s}
                        else:
                            out[fs.name] = {
                                "_as": "base64", 
                                "value": base64.b64encode(b).decode("ascii"), 
                                "_len": len(b)
                            }
                    known += 1

                elif fs.kind == "repeated_int32":
                    arr = out.setdefault(fs.name, [])
                    if wire == 0:
                        arr.append(int(r.read_varint(64)))
                        known += 1
                    elif wire == 2 and fs.packed_ok:
                        ln = r.read_varint(32)
                        sub_end = r.tell() + ln
                        while r.tell() < sub_end:
                            arr.append(int(r.read_varint(64)))
                        known += 1
                    else:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), "note": "wire不匹配 for repeated_int32"
                        })
                        out["_fatal"] = True
                        break

                elif fs.kind in ("message", "repeated_message"):
                    if wire != 2:
                        raw = r.skip_field(field, wire)
                        unknown += 1
                        out["_unknown"].append({
                            "field": field, "wire": wire, "pos": key_pos, 
                            "raw": _hex_preview(raw), "note": "wire不匹配，期望len-delimited for message"
                        })
                        out["_fatal"] = True
                        break
                    ln = r.read_varint(32)
                    b = r.read_bytes(ln)
                    nested_type = fs.msg or "Unknown"
                    nested_obj = self._decode_nested_smart(b, nested_type, depth + 1)

                    if fs.kind == "message":
                        out[fs.name] = nested_obj
                    else:
                        out.setdefault(fs.name, []).append(nested_obj)
                    known += 1

                else:
                    raw = r.skip_field(field, wire)
                    unknown += 1
                    out["_unknown"].append({
                        "field": field, "wire": wire, "pos": key_pos, 
                        "raw": _hex_preview(raw), "note": f"未处理kind={fs.kind}"
                    })
                    out["_fatal"] = True
                    break

            except ProtoDecodeError as e:
                out["_unknown"].append({
                    "field": field, "wire": wire, "pos": key_pos, 
                    "raw": "", "note": f"解码错误: {e}"
                })
                out["_fatal"] = True
                break

            if r.tell() == pos_before:
                out["_unknown"].append({
                    "field": field, "wire": wire, "pos": key_pos, 
                    "raw": "", "note": "无进展（bug）"
                })
                out["_fatal"] = True
                break

        return DecodeResult(
            obj=out, 
            fatal=bool(out.get("_fatal")), 
            unknown_count=unknown, 
            known_count=known, 
            end_pos=r.tell()
        )

    def _decode_nested_smart(self, b: bytes, preferred_type: str, depth: int) -> Any:
        """智能解码嵌套消息"""
        if depth > self.max_depth:
            return {
                "_type": preferred_type, 
                "_note": "达到最大深度", 
                "_len": len(b), 
                "_hex": _hex_preview(b)
            }

        # 优先尝试指定类型
        if preferred_type in SCHEMAS and SCHEMAS[preferred_type]:
            res = self.decode_as(preferred_type, b, start=0, depth=depth, limit=len(b))
            if not res.fatal and res.known_count > 0:
                res.obj.pop("_fatal", None)
                return res.obj

        # 否则在常见类型中猜测
        best_score = -1e9
        best_obj: Optional[Dict[str, Any]] = None
        best_type: Optional[str] = None

        for t in (
            "Zproto.MahjongSyncMessage",
            "Zproto.MahjongSyncOpMessage",
            "Zproto.MahjongPlayerShow",
            "Zproto.MahjongOpenMeld",
            "Zproto.MahjongOperation",
            "Zproto.MahjongPlayerSelf",
        ):
            res = self.decode_as(t, b, start=0, depth=depth, limit=len(b))
            score = self._score(res, len(b))
            if score > best_score:
                best_score = score
                best_obj = res.obj
                best_type = t

        if best_obj is not None and best_score > 0:
            best_obj.pop("_fatal", None)
            best_obj["_guessed"] = True
            best_obj["_guessed_type"] = best_type
            return best_obj

        # 回退到UTF-8或base64
        s = _try_utf8(b)
        if s is not None:
            return {"_as": "utf8", "value": s, "_len": len(b)}
        
        return {"_as": "bytes", "base64": base64.b64encode(b).decode("ascii"), "_len": len(b)}

    def _score(self, res: DecodeResult, total_len: int) -> float:
        """评分解码结果"""
        if res.fatal:
            return -1000.0
        coverage = res.end_pos / max(1, total_len)
        return (res.known_count * 10.0) - (res.unknown_count * 1.5) + (coverage * 5.0)

    def find_best_offset(self, data: bytes, msg_types: List[str], 
                         max_offset: int = 512) -> Tuple[int, str, DecodeResult]:
        """找到最佳偏移和消息类型"""
        best_score = -1e18
        best_off = 0
        best_type = msg_types[0]
        best_res: Optional[DecodeResult] = None

        max_offset = min(max_offset, len(data))
        for off in range(0, max_offset):
            for t in msg_types:
                res = self.decode_as(t, data, start=off, depth=0, limit=len(data))
                score = self._score(res, len(data) - off)

                # 非法字段0强烈惩罚
                if res.obj.get("_unknown"):
                    u0 = res.obj["_unknown"][0]
                    if u0.get("field") == 0:
                        score -= 500.0

                if score > best_score:
                    best_score, best_off, best_type, best_res = score, off, t, res

        assert best_res is not None
        return best_off, best_type, best_res

    def guess_and_decode(self, data: bytes, candidates: List[str], 
                         max_offset: int = 512) -> Tuple[str, Dict[str, Any]]:
        """猜测并解码"""
        off, t, res = self.find_best_offset(data, candidates, max_offset=max_offset)
        obj = res.obj
        fatal = obj.pop("_fatal", False)
        obj["_start_offset"] = off
        obj["_input_len"] = len(data)
        obj["_payload_len"] = len(data) - off
        obj["_guessed_type"] = t
        obj["_fatal"] = fatal
        return t, obj


# ===== CLI =====

def parse_bin(path: str, max_offset: int, allow_zstd: bool) -> Dict[str, Any]:
    """解析二进制文件"""
    with open(path, "rb") as f:
        raw = f.read()

    payload = raw
    zstd_used = False
    zstd_note = ""
    
    if allow_zstd:
        payload, zstd_used, zstd_note = maybe_zstd_decompress(raw)

    dec = ProtobufSmartDecoder(max_depth=10)

    candidates = [
        "Zproto.MahjongSyncMessage",
        "Zproto.MahjongSyncOpMessage",
        "Zproto.MahjongPlayerShow",
        "Zproto.MahjongOpenMeld",
        "Zproto.MahjongOperation",
        "Zproto.MahjongPlayerSelf",
    ]

    guessed, obj = dec.guess_and_decode(payload, candidates, max_offset=max_offset)

    summary = {
        "guessed_message": guessed,
        "start_offset": obj.get("_start_offset", 0),
        "zstd": bool(zstd_used),
        "zstd_note": zstd_note,
        "input_len": len(raw),
        "payload_len": len(payload),
        "unknown_fields": len(obj.get("_unknown", [])),
    }
    
    return {"_summary": summary, "data": obj}


def main():
    ap = argparse.ArgumentParser(description="麻将智能Protobuf解码器")
    ap.add_argument("path", help="输入的.bin文件")
    ap.add_argument("--max-offset", type=int, default=512, help="探测偏移范围 [0, max-offset)")
    ap.add_argument("--no-zstd", action="store_true", help="禁用zstd自动解压")
    ap.add_argument("--json", dest="json_out", default="", help="输出JSON到文件")
    ap.add_argument("--pretty", action="store_true", help="美化JSON输出")
    args = ap.parse_args()

    out = parse_bin(args.path, max_offset=args.max_offset, allow_zstd=(not args.no_zstd))
    txt = json.dumps(out, ensure_ascii=False, indent=2 if args.pretty else None)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(txt)

    print(txt)


if __name__ == "__main__":
    main()