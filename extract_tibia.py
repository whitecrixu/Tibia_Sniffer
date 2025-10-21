#!/usr/bin/env python3
"""
Tibia opcode + byte extractor

Usage: python3 extract_tibia.py --pcap file.pcap
       python3 extract_tibia.py --iface eth0

By default it extracts 1-byte opcode at payload offset 0 and 1-byte "byte" at offset 1.
Both offsets and lengths are configurable.

Includes --test mode which generates a small pcap and demonstrates extraction.
"""
import argparse
import platform
import os
import re
import json
from datetime import datetime
import tempfile
import os
import sys
import signal
import json
import csv
from datetime import datetime
from tibiadata_client import derive_service_from_ports
from binascii import unhexlify
try:
    import netifaces
except Exception:
    netifaces = None

try:
    from scapy.all import rdpcap, sniff, TCP, Raw, IP, wrpcap, Ether, conf
except Exception as e:
    print("scapy is required. Install with: pip install scapy")
    raise


def parse_payload(payload: bytes, opcode_offset: int, opcode_len: int, byte_offset: int, byte_len: int):
    """Return dict with extracted fields or None if payload too short."""
    if payload is None:
        return None
    need = max(opcode_offset + opcode_len, byte_offset + byte_len)
    if len(payload) < need:
        return None
    opcode_bytes = payload[opcode_offset:opcode_offset + opcode_len]
    other_bytes = payload[byte_offset:byte_offset + byte_len]
    return {
        "opcode_raw": opcode_bytes,
        "opcode_int": int.from_bytes(opcode_bytes, byteorder='big', signed=False),
        "byte_raw": other_bytes,
        "byte_int": int.from_bytes(other_bytes, byteorder='big', signed=False),
    }


def format_bytes(b: bytes):
    return ' '.join(f"0x{x:02X}" for x in b)


def parse_tibia_frame(payload: bytes):
    """Parse Tibia framed payload: [length:2 little-endian][opcode:1][payload...]"""
    if payload is None or len(payload) < 3:
        return None
    opcode = payload[2]
    other = payload[3:4] if len(payload) >= 4 else b""
    return {
        "opcode_raw": bytes([opcode]),
        "opcode_int": opcode,
        "byte_raw": other,
        "byte_int": int.from_bytes(other, byteorder='big', signed=False) if other else 0,
    }


# --- Optional XTEA decrypt for Tibia game packets ---
def _xtea_decrypt_block(v0: int, v1: int, k: tuple[int, int, int, int]):
    # Standard XTEA decryption (32 rounds)
    delta = 0x9E3779B9
    sumv = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sumv + k[(sumv >> 11) & 3]))) & 0xFFFFFFFF
        sumv = (sumv - delta) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sumv + k[sumv & 3]))) & 0xFFFFFFFF
    return v0, v1


def _to_u32_le(b: bytes):
    return int.from_bytes(b, 'little')


def xtea_decrypt_le(data: bytes, key16: bytes) -> bytes:
    if len(key16) != 16:
        raise ValueError('XTEA key must be 16 bytes')
    k = (_to_u32_le(key16[0:4]), _to_u32_le(key16[4:8]), _to_u32_le(key16[8:12]), _to_u32_le(key16[12:16]))
    out = bytearray()
    blocks = len(data) // 8
    for i in range(blocks):
        blk = data[i*8:(i+1)*8]
        v0 = _to_u32_le(blk[0:4])
        v1 = _to_u32_le(blk[4:8])
        d0, d1 = _xtea_decrypt_block(v0, v1, k)
        out += d0.to_bytes(4, 'little') + d1.to_bytes(4, 'little')
    return bytes(out)


def parse_tibia_frame_xtea(payload: bytes, key16: bytes):
    """Parse Tibia framed payload with XTEA: [len:2][enc(payload...)] -> dec=[checksum:2][opcode:1]..."""
    if payload is None or len(payload) < 2 + 8:
        return None
    enc = payload[2:]
    # align to 8 bytes
    n = len(enc) - (len(enc) % 8)
    if n < 8:
        return None
    dec = xtea_decrypt_le(enc[:n], key16)
    # After decryption, Tibia typically has 2-byte checksum, then opcode
    if len(dec) < 3:
        return None
    opcode = dec[2]
    other = dec[3:4] if len(dec) >= 4 else b""
    return {
        "opcode_raw": bytes([opcode]),
        "opcode_int": opcode,
        "byte_raw": other,
        "byte_int": int.from_bytes(other, byteorder='big', signed=False) if other else 0,
    }

# --- Byte name resolution for selected opcodes ---
SPEAK_CLASSES_MAP = {
    1: 'SAY',
    2: 'WHISPER',
    3: 'YELL',
    4: 'PRIVATE_FROM',
    5: 'PRIVATE_TO',
    6: 'CHANNEL_MANAGER',
    7: 'CHANNEL_Y',
    8: 'CHANNEL_O',
    9: 'SPELL_USE',
    10: 'PRIVATE_NP',
    11: 'NPC_UNKNOWN',
    12: 'PRIVATE_PN',
    13: 'BROADCAST',
    14: 'CHANNEL_R1',
    15: 'PRIVATE_RED_FROM',
    16: 'PRIVATE_RED_TO',
    36: 'MONSTER_SAY',
    37: 'MONSTER_YELL',
}

FIGHT_MODE_MAP = {
    1: 'OFFENSIVE',
    2: 'BALANCED',
    3: 'DEFENSIVE',
}

QUICKLOOT_FILTER_MAP = {
    0: 'SKIPPED_LOOT',
    1: 'ACCEPTED_LOOT',
}

QUICKLOOT_TYPE_MAP = {
    0: 'LOOT_SINGLE',
    1: 'LOOT_ALL_CORPSES',
    2: 'LOOT_NEAR_PLAYER',
}

LOOT_CONTAINER_ACTION_MAP = {
    0: 'LC_SET_MANAGED',          # setManagedContainer(..., true)
    1: 'LC_CLEAR_MANAGED',        # clearManagedContainer(..., true)
    2: 'LC_OPEN_MANAGED',         # openManagedContainer(..., true)
    3: 'LC_SET_FALLBACK',         # setQuickLootFallback
    4: 'LC_SET_LOCAL',            # setManagedContainer(..., false)
    5: 'LC_CLEAR_LOCAL',          # clearManagedContainer(..., false)
    6: 'LC_OPEN_LOCAL',           # openManagedContainer(..., false)
}

def _resolve_byte_name(op_int: int, opcode_name: str | None, byte_val: int) -> str | None:
    # Extended opcode (otclient) first byte is the extended opcode number
    if op_int == 0x32 or (opcode_name and opcode_name.lower() == 'parseextendedopcode'):
        return f'EXTOP_{byte_val}'
    # parseSay: first byte is SpeakClasses
    if opcode_name and opcode_name.lower() == 'parsesay':
        return SPEAK_CLASSES_MAP.get(byte_val)
    # parseFightModes: first byte is fight mode
    if opcode_name and opcode_name.lower() == 'parsefightmodes':
        return FIGHT_MODE_MAP.get(byte_val)
    # parseQuickLootBlackWhitelist: first byte is QuickLootFilter_t
    if opcode_name and opcode_name.lower() == 'parsequicklootblackwhitelist':
        return QUICKLOOT_FILTER_MAP.get(byte_val)
    # parseQuickLoot: first byte is lootType
    if opcode_name and opcode_name.lower() == 'parsequickloot':
        return QUICKLOOT_TYPE_MAP.get(byte_val)
    # parseLootContainer: first byte is action
    if opcode_name and opcode_name.lower() == 'parselootcontainer':
        return LOOT_CONTAINER_ACTION_MAP.get(byte_val)
    # parseVipGroupActions: first byte is action 0x01 add, 0x02 edit, 0x03 remove
    if opcode_name and opcode_name.lower() == 'parsevipgroupactions':
        return {1:'VIP_ADD_GROUP',2:'VIP_EDIT_GROUP',3:'VIP_REMOVE_GROUP'}.get(byte_val)
    # parseLookInTrade: first byte is 0x01 if counterOffer, else 0x00
    if opcode_name and opcode_name.lower() == 'parselookintrade':
        return 'COUNTER_OFFER' if byte_val == 1 else 'OFFER'
    # parseToggleMount: byte!=0 -> ON
    if opcode_name and opcode_name.lower() == 'parsetogglemount':
        return 'MOUNT_ON' if byte_val != 0 else 'MOUNT_OFF'
    # parseAutoWalk: first byte is number of directions
    if opcode_name and opcode_name.lower() == 'parseautowalk':
        return 'NUMDIRS'
    return None

def _load_default_opcode_mapping(verbose: bool = False):
    """Load opcode mapping from New-folder--2-/enhanced_mapping.json if present."""
    try:
        default_map = os.path.join(os.path.dirname(__file__), 'New-folder--2-', 'enhanced_mapping.json')
        if not os.path.isfile(default_map):
            return None
        with open(default_map, 'r', encoding='utf-8') as f:
            mapping_json = json.load(f)
        opcode_map = {}
        for k, v in mapping_json.get('movement_opcodes', {}).items():
            try:
                code = int(k, 16)
                name = v.get('direction')
                if name:
                    opcode_map[code] = f"MOVE_{name.upper()}"
            except Exception:
                pass
        for k, v in mapping_json.get('creature_opcodes', {}).items():
            try:
                code = int(k, 16)
                action = v.get('action')
                if action:
                    opcode_map[code] = str(action)
            except Exception:
                pass
        if verbose and opcode_map:
            print(f"Loaded opcode mapping entries: {len(opcode_map)}")
        return opcode_map if opcode_map else None
    except Exception as e:
        if verbose:
            print(f"Warning: failed to load opcode mapping: {e}")
        return None


def load_opcode_map_from_crystalserver(cs_root: str, verbose: bool = False):
    """Parse crystalserver ProtocolGame client->server opcode switch and return {int: name} mapping.

    Looks into src/server/network/protocol/protocolgame.cpp and extracts case 0xNN labels and the first
    significant action or parse function call to derive a human-readable name.
    """
    try:
        pg_path = os.path.join(cs_root, 'src', 'server', 'network', 'protocol', 'protocolgame.cpp')
        with open(pg_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        if verbose:
            print(f"Failed to read crystalserver ProtocolGame: {e}")
        return None

    # Narrow to parsePacketFromDispatcher switch block for robustness
    m = re.search(r"void\s+ProtocolGame::parsePacketFromDispatcher\s*\(.*?\)\s*\{(.*?)\n\}", text, re.DOTALL)
    block = m.group(1) if m else text

    mapping: dict[int, str] = {}
    # Iterate case blocks
    for mcase in re.finditer(r"case\s+0x([0-9A-Fa-f]{1,2}):\s*(.*?)\bbreak\s*;", block, re.DOTALL):
        hexcode = mcase.group(1)
        body = mcase.group(2)
        code = int(hexcode, 16)
        name = None
        # Try parse* function call
        mparse = re.search(r"\b(parse[A-Z_][A-Za-z0-9_]*)\s*\(", body)
        if mparse:
            name = mparse.group(1)
        else:
            # g_game() actions
            mmove = re.search(r"g_game\(\)\.(playerMove)\([^\)]*DIRECTION_([A-Z]+)\)", body)
            if mmove:
                name = f"{mmove.group(1)}_{mmove.group(2).title()}"
            mturn = re.search(r"g_game\(\)\.(playerTurn)\([^\)]*DIRECTION_([A-Z]+)\)", body)
            if not name and mturn:
                name = f"{mturn.group(1)}_{mturn.group(2).title()}"
            # Simple g_game() calls like playerAcceptTrade, playerCloseShop, etc.
            if not name:
                mg = re.search(r"g_game\(\)\.(player[A-Za-z0-9_]+)\s*\(", body)
                if mg:
                    name = mg.group(1)
        # Comments sometimes carry hint
        if not name:
            mcom = re.search(r"/\*\s*([^*]+?)\s*\*/", body)
            if mcom:
                name = mcom.group(1).strip().replace(' ', '_')
        # Special-case extended opcode
        if code == 0x32 and not name:
            name = 'parseExtendedOpcode'
        if not name:
            name = f"opcode_0x{hexcode.upper()}"
        mapping[code] = name

    if verbose:
        print(f"Extracted {len(mapping)} opcode mappings from crystalserver")
    return mapping or None


def load_server_opcode_map_from_crystalserver(cs_root: str, verbose: bool = False):
    """Heuristically extract server->client opcode mapping by scanning send* methods
    for addByte(0xNN) style writes in ProtocolGame. Returns {int: 'sendFunctionName'}.
    """
    try:
        pg_path = os.path.join(cs_root, 'src', 'server', 'network', 'protocol', 'protocolgame.cpp')
        with open(pg_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        if verbose:
            print(f"Failed to read crystalserver ProtocolGame for server map: {e}")
        return None

    mapping: dict[int, str] = {}

    # Find send* functions: e.g., void ProtocolGame::sendXxx(...){ ... }
    for mfun in re.finditer(r"void\s+ProtocolGame::(send[A-Za-z0-9_]+)\s*\([^)]*\)\s*\{(.*?)\}", text, re.DOTALL):
        fname = mfun.group(1)
        body = mfun.group(2)
        # Common patterns for writing opcode byte
        patterns = [
            r"addByte\s*\(\s*0x([0-9A-Fa-f]{1,2})\s*\)",
            r"addU8\s*\(\s*0x([0-9A-Fa-f]{1,2})\s*\)",
            r"write\s*<\s*uint8_t\s*>\s*\(\s*0x([0-9A-Fa-f]{1,2})\s*\)",
        ]
        found = None
        for pat in patterns:
            mm = re.search(pat, body)
            if mm:
                found = mm.group(1)
                break
        if found:
            code = int(found, 16)
            # Keep first sender name if multiple map to same code; prefer a more descriptive one if later found
            if code not in mapping:
                mapping[code] = fname

    if verbose:
        print(f"Extracted {len(mapping)} server opcode mappings from crystalserver")
    return mapping or None


def process_packet(pkt, args, writer_state=None, on_event=None, on_event_obj=None):
    # extract TCP payload
    if not pkt.haslayer(TCP):
        return
    if not pkt.haslayer(IP):
        return
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
    if not payload:
        return

    ts_val = getattr(pkt, 'time', None)
    try:
        if ts_val is not None:
            ts = datetime.fromtimestamp(float(ts_val)).isoformat()
        else:
            ts = datetime.now().isoformat()
    except Exception:
        ts = datetime.now().isoformat()

    src = pkt[IP].src
    dst = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    svc = derive_service_from_ports(sport, dport)

    # Warn once if we are seeing game traffic without XTEA key
    if getattr(args, 'tibia_frame', False) and getattr(args, 'xtea_key_bytes', None) is None:
        ports_interest = getattr(args, 'ports', None) or [getattr(args, 'port', None)]
        try:
            if not getattr(args, '_warned_missing_xtea', False) and 7171 in ports_interest:
                msg = '[warn] Observing Tibia game traffic (7171) without XTEA key; opcode/byte will be raw/incorrect until a key is provided.'
                print(msg)
                if on_event:
                    try:
                        on_event(msg)
                    except Exception:
                        pass
                args._warned_missing_xtea = True
        except Exception:
            pass

    # Helper to output one parsed frame
    def emit_one(res):
        # pick opcode map by direction: client->server (dport in filter ports) vs server->client (sport in filter ports)
        opcode_name = None
        ports_of_interest = args.ports if getattr(args, 'ports', None) else [args.port]
        chosen_map = None
        direction = None  # 'c2s' or 's2c'
        try:
            if dport in ports_of_interest and getattr(args, 'opcode_map', None):
                chosen_map = args.opcode_map
                direction = 'c2s'
            elif sport in ports_of_interest and getattr(args, 'server_opcode_map', None):
                chosen_map = args.server_opcode_map
                direction = 's2c'
            elif getattr(args, 'opcode_map', None):
                chosen_map = args.opcode_map
                # leave direction None if ambiguous
        except Exception:
            chosen_map = getattr(args, 'opcode_map', None)
        if chosen_map:
            try:
                opcode_name = chosen_map.get(res['opcode_int'])
            except Exception:
                opcode_name = None
        byte_name = _resolve_byte_name(res['opcode_int'], opcode_name, res['byte_int'])
        text_line = (
            f"{ts} {src}:{sport} -> {dst}:{dport}"
            + (f" [{svc}]" if svc else "")
            + " | "
            f"OPCODE={res['opcode_int']}({format_bytes(res['opcode_raw'])})"
            + (f"[{opcode_name}]" if opcode_name else "")
            + f" | BYTE={res['byte_int']}({format_bytes(res['byte_raw'])})"
            + (f"[{byte_name}]" if byte_name else "")
        )
        obj_event = {
            'timestamp': ts,
            'src': src,
            'dst': dst,
            'sport': sport,
            'dport': dport,
            'direction': direction,
            'service': svc,
            'opcode_int': res['opcode_int'],
            'opcode_raw': res['opcode_raw'].hex(),
            'opcode_name': opcode_name,
            'byte_int': res['byte_int'],
            'byte_raw': res['byte_raw'].hex(),
            'byte_name': byte_name,
        }
        if args.output in ('text', 'default'):
            print(text_line)
        if args.output == 'json' or args.output == 'all':
            j = {
                'timestamp': ts,
                'src': src,
                'dst': dst,
                'sport': sport,
                'dport': dport,
                'opcode_int': res['opcode_int'],
                'opcode_raw': res['opcode_raw'].hex(),
                'opcode_name': opcode_name,
                'service': svc,
                'byte_int': res['byte_int'],
                'byte_raw': res['byte_raw'].hex(),
                'byte_name': byte_name,
            }
            print(json.dumps(j))
        if args.output in ('csv', 'all') and writer_state is not None:
            w = writer_state.get('writer')
            if w:
                w.writerow({
                    'timestamp': ts,
                    'src': src,
                    'dst': dst,
                    'sport': sport,
                    'dport': dport,
                    'opcode_int': res['opcode_int'],
                    'opcode_raw': res['opcode_raw'].hex(),
                    'opcode_name': opcode_name or '',
                    'service': svc or '',
                    'byte_int': res['byte_int'],
                    'byte_raw': res['byte_raw'].hex(),
                    'byte_name': byte_name or '',
                })
        if on_event:
            try:
                on_event(text_line)
            except Exception as ex:
                print(f"[SNIFFER] on_event callback failed: {ex}")
        if on_event_obj:
            try:
                on_event_obj(obj_event)
            except Exception as ex:
                if getattr(args, 'verbose', False):
                    print(f"[SNIFFER] on_event_obj callback failed: {ex}")

    # If Tibia framed parsing requested, use per-flow buffer and parse complete frames
    if getattr(args, 'tibia_frame', False):
        if not hasattr(args, '_streams'):
            args._streams = {}
        key = (src, sport, dst, dport)
        buf = args._streams.get(key)
        if buf is None:
            buf = bytearray()
            args._streams[key] = buf
        buf += payload

        # parse as many complete frames as available in buffer
        while True:
            if len(buf) < 3:
                break
            # Try to find a plausible frame start. If not plausible, drop one byte (resync).
            plausible = False
            # 2-byte little-endian length (encrypted payload length for XTEA, or plain payload length otherwise)
            frame_len = int.from_bytes(buf[0:2], 'little')
            total = 2 + frame_len
            # Heuristics: reasonable size and fits in current buffer
            if 3 <= total <= len(buf):
                if getattr(args, 'xtea_key_bytes', None):
                    # XTEA payload must be >=8 and 8-byte aligned
                    if frame_len >= 8 and (frame_len % 8) == 0:
                        plausible = True
                else:
                    plausible = True
            if not plausible:
                # Drop one byte to attempt resync on next iteration
                del buf[:1]
                continue
            # slice one frame
            content = bytes(buf[2:total])
            del buf[:total]

            if getattr(args, 'xtea_key_bytes', None):
                # decrypt exactly this frame
                if len(content) < 8 or (len(content) % 8) != 0:
                    if args.verbose:
                        print(f"[warn] XTEA frame size not 8-byte aligned: {len(content)}; skipping")
                    continue
                try:
                    dec = xtea_decrypt_le(content, args.xtea_key_bytes)
                    if len(dec) < 3:
                        if args.verbose:
                            print("[warn] decrypted frame too short")
                        continue
                    # Prefer 4-byte Adler32 checksum scheme: [chk32:4][opcode:1]...
                    opcode = None
                    other = b""
                    try:
                        import zlib as _z
                        if len(dec) >= 5:
                            chk32 = int.from_bytes(dec[0:4], 'little')
                            body32 = dec[4:]
                            adl32 = _z.adler32(body32) & 0xFFFFFFFF
                            if chk32 == adl32:
                                opcode = dec[4]
                                other = dec[5:6] if len(dec) >= 6 else b""
                        if opcode is None and len(dec) >= 3:
                            # Fallback: 2-byte checksum heuristics
                            chk16 = int.from_bytes(dec[0:2], 'little')
                            body16 = dec[2:]
                            sum16 = (sum(body16) & 0xFFFF) if body16 else 0
                            adl16 = (_z.adler32(body16) & 0xFFFF) if body16 else 0
                            if chk16 in (sum16, adl16):
                                opcode = dec[2]
                                other = dec[3:4] if len(dec) >= 4 else b""
                        if opcode is None:
                            # As a last resort, assume no checksum
                            opcode = dec[0]
                            other = dec[1:2] if len(dec) >= 2 else b""
                        else:
                            if args.verbose and len(dec) >= 5:
                                if 'chk32' in locals():
                                    if chk32 != adl32:
                                        print("[warn] 4-byte checksum mismatch; fell back to 2-byte/no-chk parse")
                    except Exception:
                        # Non-fatal; take first bytes
                        opcode = dec[0]
                        other = dec[1:2] if len(dec) >= 2 else b""
                    res = {
                        'opcode_raw': bytes([opcode]),
                        'opcode_int': opcode,
                        'byte_raw': other,
                        'byte_int': int.from_bytes(other, 'big', signed=False) if other else 0,
                    }
                    emit_one(res)
                except Exception as e:
                    if args.verbose:
                        print(f"[warn] XTEA decrypt failed: {e}")
                    # try plain parse as last resort
                    if len(content) >= 1:
                        opcode = content[0]
                        other = content[1:2] if len(content) >= 2 else b""
                        res = {
                            'opcode_raw': bytes([opcode]),
                            'opcode_int': opcode,
                            'byte_raw': other,
                            'byte_int': int.from_bytes(other, 'big', signed=False) if other else 0,
                        }
                        emit_one(res)
            else:
                # plain framed: first byte is opcode, second is the following byte
                if len(content) >= 1:
                    opcode = content[0]
                    other = content[1:2] if len(content) >= 2 else b""
                    res = {
                        'opcode_raw': bytes([opcode]),
                        'opcode_int': opcode,
                        'byte_raw': other,
                        'byte_int': int.from_bytes(other, 'big', signed=False) if other else 0,
                    }
                    emit_one(res)
        return

    # Else: raw offsets from the single TCP segment
    res = parse_payload(payload, args.opcode_offset, args.opcode_len, args.byte_offset, args.byte_len)
    if res is None:
        if args.verbose:
            print(f"[{datetime.now()}] pkt too short: len={len(payload)}")
        return
    emit_one(res)


def read_pcap(path, args):
    try:
        pkts = rdpcap(path)
    except FileNotFoundError:
        print(f"pcap file not found: {path}")
        return
    except Exception as e:
        print(f"error reading pcap: {e}")
        return

    for pkt in pkts:
        process_packet(pkt, args)


def live_sniff(args, stop_event=None, on_event=None, on_event_obj=None):
    # Prefer pcap backend and non-promiscuous mode for stability (especially on loopback)
    try:
        conf.use_pcap = True
        conf.sniff_promisc = False
    except Exception:
        pass
    # Auto-load mapping when called outside CLI main (e.g., from GUI)
    if getattr(args, 'opcode_map', None) is None:
        args.opcode_map = _load_default_opcode_mapping(verbose=getattr(args, 'verbose', False))
    # Fallback: try to auto-load mapping JSON dumped from crystalserver if present
    if getattr(args, 'opcode_map', None) is None:
        try_paths = [
            os.path.join(os.getcwd(), 'crystalserver_opcodes.json'),
            os.path.join(os.path.dirname(__file__), 'crystalserver_opcodes.json'),
        ]
        for mp in try_paths:
            if os.path.isfile(mp):
                try:
                    with open(mp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    opmap = {}
                    if isinstance(data, dict):
                        for k, v in data.items():
                            try:
                                ks = str(k)
                                if ks.lower().startswith('0x'):
                                    kk = int(ks, 16)
                                else:
                                    kk = int(ks)
                                opmap[kk] = str(v)
                            except Exception:
                                continue
                    if opmap:
                        args.opcode_map = opmap
                        if getattr(args, 'verbose', False):
                            print(f"Auto-loaded opcode mapping from {mp}: {len(opmap)} entries")
                        break
                except Exception:
                    pass
    # Fallback for server->client mapping JSON
    if getattr(args, 'server_opcode_map', None) is None:
        try_paths = [
            os.path.join(os.getcwd(), 'crystalserver_opcodes_server.json'),
            os.path.join(os.path.dirname(__file__), 'crystalserver_opcodes_server.json'),
        ]
        for mp in try_paths:
            if os.path.isfile(mp):
                try:
                    with open(mp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    opmap = {}
                    if isinstance(data, dict):
                        for k, v in data.items():
                            try:
                                ks = str(k)
                                kk = int(ks, 16) if ks.lower().startswith('0x') else int(ks)
                                opmap[kk] = str(v)
                            except Exception:
                                continue
                    if opmap:
                        args.server_opcode_map = opmap
                        if getattr(args, 'verbose', False):
                            print(f"Auto-loaded server opcode mapping from {mp}: {len(opmap)} entries")
                        break
                except Exception:
                    pass

    # prepare output writer state
    writer_state = {'writer': None, 'file': None}
    if args.output in ('csv', 'all') and args.outfile:
        f = open(args.outfile, 'w', newline='')
        writer = csv.DictWriter(
            f,
            fieldnames=['timestamp','src','dst','sport','dport','service','opcode_int','opcode_raw','opcode_name','byte_int','byte_raw','byte_name']
        )
        writer.writeheader()
        writer_state['writer'] = writer
        writer_state['file'] = f

    # Build filter for one or many ports
    ports = getattr(args, 'ports', None)
    if ports:
        terms = [f"port {p}" for p in ports]
        flt = "tcp and (" + " or ".join(terms) + ")"
    else:
        # Build filter for one or many ports
        ports = getattr(args, 'ports', None)
        if ports:
            terms = [f"port {p}" for p in ports]
            flt = "tcp and (" + " or ".join(terms) + ")"
        else:
            flt = f"tcp and port {args.port}"
    start_msg = f"Starting live sniff on interface {args.iface or 'default'} filter='{flt}', count={args.count or 'infinite'} output={args.output} outfile={args.outfile}"
    print(start_msg)
    if on_event:
        try:
            on_event(start_msg)
        except Exception:
            pass

    # signal handling for graceful shutdown
    def _stop(signum, frame):
        if stop_event is not None:
            try:
                stop_event.set()
            except Exception:
                pass
        else:
            # fallback: exit
            raise KeyboardInterrupt()

    try:
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
    except Exception:
        # signals may not be available on some platforms or threads
        pass

    # Track captured packet count when --count is provided
    captured = {'n': 0}
    scapy_count = args.count if args.count is not None else 0  # 0 means infinite for scapy

    def _prn(p):
        try:
            process_packet(p, args, writer_state, on_event=on_event, on_event_obj=on_event_obj)
            if args.count is not None:
                captured['n'] += 1
        except Exception as e:
            if args.verbose:
                print(f"error processing packet: {e}")

    # sniff can accept stop_filter to break when stop_event is set
    def _stop_filter(pkt):
        try:
            return stop_event is not None and stop_event.is_set()
        except Exception:
            return False

    try:
        # Robust loop: run short sniff windows and restart on occasional backend hiccups (common on loopback)
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            try:
                sniff(
                    filter=flt,
                    prn=_prn,
                    iface=args.iface,
                    count=scapy_count,
                    stop_filter=_stop_filter,
                    store=False,
                    promisc=False,
                    timeout=3,
                )
                # If a finite count was requested and reached, exit
                if args.count is not None and captured['n'] >= args.count:
                    break
            except KeyboardInterrupt:
                msg = '\nStopping capture...'
                print(msg)
                if on_event:
                    try:
                        on_event(msg)
                    except Exception:
                        pass
                break
            except Exception as e:
                warn = f"sniff backend warning: {e}; restarting..."
                if getattr(args, 'verbose', False):
                    print(warn)
                if on_event:
                    try:
                        on_event(warn)
                    except Exception:
                        pass
                # brief backoff
                try:
                    import time as _t
                    _t.sleep(0.2)
                except Exception:
                    pass
    finally:
        if on_event:
            try:
                on_event('Capture stopped.')
            except Exception:
                pass
        if writer_state.get('file'):
            writer_state['file'].close()


def list_interfaces(iface_type='any'):
    """Return list of interface names filtered by type: 'any','wlan','eth'"""
    if netifaces is None:
        print('netifaces module not installed; cannot list interfaces. Install with: pip install netifaces')
        return []
    ifaces = netifaces.interfaces()
    if iface_type in ('any', None):
        return ifaces
    filtered = []
    for ifname in ifaces:
        # naive detection: wlan interfaces often start with 'wlan' or 'wl', ethernet 'eth' or 'en'
        low = ifname.lower()
        if iface_type == 'wlan' and (low.startswith('wlan') or low.startswith('wl')):
            filtered.append(ifname)
        elif iface_type == 'eth' and (low.startswith('eth') or low.startswith('en')):
            filtered.append(ifname)
    return filtered


def make_test_pcap(path):
    # Create two TCP packets with small payloads that contain opcode and byte
    # We'll craft minimal IP/TCP layers; these pcap packets are for offline testing only
    p1 = Ether()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(sport=1234, dport=7171)/b"\x10\xFF\xAA\x00"
    p2 = Ether()/IP(src='3.3.3.3', dst='4.4.4.4')/TCP(sport=2345, dport=7171)/b"\x01\x02"
    wrpcap(path, [p1, p2])


def auto_extract_xtea(proc_hint='Tibia', max_bytes=64*1024*1024, verbose=False):
    """Best-effort attempt to extract XTEA key from a running Tibia process."""
    if platform.system() != 'Linux':
        return None, 'Auto XTEA extraction is available only on Linux.'
    try:
        import xtea_mem_extractor as xme
    except Exception as exc:
        return None, f'Auto XTEA unavailable: {exc}'

    pid = None
    try:
        hint = (proc_hint or 'Tibia').strip()
        if hint.isdigit():
            pid = int(hint)
        else:
            pid = xme._find_pid_by_name(hint)
    except Exception as exc:
        return None, f'Auto XTEA process lookup failed: {exc}'

    if not pid:
        return None, f'Process matching {proc_hint!r} not found.'

    if verbose:
        print(f'[auto-xtea] Attaching to PID {pid}')

    try:
        xme._ptrace(xme.PTRACE_ATTACH, pid)
    except Exception as exc:
        return None, f'ptrace attach failed (run as root? ptrace_scope=0?): {exc}'

    try:
        if not xme._wait_stopped(pid):
            return None, 'Process did not stop after ptrace attach.'
        counts = xme._scan_candidates(pid, max_total_bytes=max_bytes)
        if not counts:
            return None, 'Auto XTEA found no candidates.'
        best_key, best_cnt = counts.most_common(1)[0]
        if verbose:
            print(f'[auto-xtea] Best candidate count={best_cnt}')
        return best_key, f'Auto XTEA candidate (count={best_cnt}) from PID {pid}'
    finally:
        try:
            xme._ptrace(xme.PTRACE_DETACH, pid)
        except Exception:
            pass

def main(argv=None):
    parser = argparse.ArgumentParser(description='Tibia OPCODE + Byte extractor')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--pcap', help='Read packets from pcap file')
    group.add_argument('--iface', help='Live capture interface')
    parser.add_argument('--port', type=int, default=7171, help='TCP port to filter (default 7171)')
    parser.add_argument('--ports', type=str, help='Comma-separated list of TCP ports to filter (overrides --port)')
    parser.add_argument('--opcode-offset', dest='opcode_offset', type=int, default=0, help='offset in payload for opcode (default 0)')
    parser.add_argument('--opcode-len', dest='opcode_len', type=int, default=1, help='length in bytes for opcode (default 1)')
    parser.add_argument('--byte-offset', dest='byte_offset', type=int, default=1, help='offset in payload for the other byte (default 1)')
    parser.add_argument('--byte-len', dest='byte_len', type=int, default=1, help='length in bytes for the other value (default 1)')
    parser.add_argument('--tibia-frame', action='store_true', help='parse Tibia framed payload: [len:2][opcode:1][payload]; overrides offsets')
    parser.add_argument('--xtea-key', dest='xtea_key', help='16-byte XTEA key as hex (32 hex chars) to decrypt game packets (used with --tibia-frame)')
    parser.add_argument('--profile', choices=['auto','login','game'], default='auto', help='Convenience profiles: login=7172 + tibia-frame, game=7171 + tibia-frame (+XTEA if provided). auto: infer 7172->login, 7171->game.')
    parser.add_argument('--count', type=int, default=None, help='number of live packets to capture (default infinite)')
    parser.add_argument('--hex', action='store_true', help='display values in hex only')
    parser.add_argument('--verbose', action='store_true', help='verbose output')
    parser.add_argument('--output', choices=['text','json','csv','all','default'], default='text', help='output format for live capture (text/json/csv/all)')
    parser.add_argument('--outfile', help='file to write CSV output (when --output csv or --output all)')
    parser.add_argument('--list-ifaces', action='store_true', help='list available network interfaces and exit')
    parser.add_argument('--iface-type', choices=['any','wlan','eth'], default='any', help='filter interfaces by type when listing or selecting')
    parser.add_argument('--select', action='store_true', help='interactive prompt to select an interface from the listed set')
    parser.add_argument('--test', action='store_true', help='run a self-test (generates a temporary pcap and parses it)')
    parser.add_argument('--auto-xtea', dest='auto_xtea', action='store_true', help='Force auto XTEA extraction from Tibia process (Linux root only)')
    parser.add_argument('--no-auto-xtea', dest='auto_xtea', action='store_false', help='Disable auto XTEA extraction')
    parser.set_defaults(auto_xtea=True)
    parser.add_argument('--tibia-proc', default='Tibia', help='Process name or PID for auto XTEA detection (default: Tibia)')
    # Mapping controls
    parser.add_argument('--mapping-json', help='Load opcode mapping from JSON file (format: { "<int or 0xhex>": "Name", ... })')
    parser.add_argument('--mapping-source', help='Path to crystalserver root to auto-extract opcode mapping from ProtocolGame (client->server)')
    parser.add_argument('--dump-mapping', help='If provided with --mapping-source, dump extracted mapping to this JSON path')

    args = parser.parse_args(argv)

    # Apply profile defaults
    if args.profile and args.profile != 'auto':
        if args.profile == 'login':
            args.port = 7172
            args.tibia_frame = True
            if args.verbose:
                print('[profile] login: port=7172, tibia-frame=ON')
        elif args.profile == 'game':
            args.port = 7171
            args.tibia_frame = True
            if args.verbose:
                print('[profile] game: port=7171, tibia-frame=ON (XTEA recommended)')

    # Parse multi-ports
    if args.ports:
        try:
            args.ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except Exception:
            print('Invalid --ports value, expected comma-separated integers like 7171,7172')
            return
    else:
        args.ports = None

    # Parse XTEA key if provided
    args.xtea_key_bytes = None
    if args.xtea_key:
        try:
            key = unhexlify(args.xtea_key.strip())
            if len(key) != 16:
                print('Invalid --xtea-key: must be 32 hex chars (16 bytes)')
                return
            args.xtea_key_bytes = key
        except Exception:
            print('Invalid --xtea-key: provide hex like 00112233445566778899AABBCCDDEEFF')
            return

    # Track whether we warned about missing XTEA / auto-frame
    args._warned_missing_xtea = False
    args._auto_tibia_frame = False

    # Load opcode mapping priority: explicit JSON -> crystalserver parse -> default enhanced_mapping.json
    args.opcode_map = None
    args.server_opcode_map = None
    if args.mapping_json:
        try:
            with open(args.mapping_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            opmap = {}
            if isinstance(data, dict):
                for k, v in data.items():
                    try:
                        kk = None
                        ks = str(k)
                        if ks.lower().startswith('0x'):
                            kk = int(ks, 16)
                        else:
                            kk = int(ks)
                        opmap[kk] = str(v)
                    except Exception:
                        continue
            args.opcode_map = opmap if opmap else None
            if args.verbose and args.opcode_map:
                print(f"Loaded opcode mapping from JSON ({args.mapping_json}): {len(args.opcode_map)} entries")
        except Exception as e:
            print(f"Warning: failed to load mapping JSON {args.mapping_json}: {e}")
    if args.opcode_map is None and args.mapping_source:
        cs_map = load_opcode_map_from_crystalserver(args.mapping_source, verbose=args.verbose)
        if cs_map:
            args.opcode_map = cs_map
            if args.dump_mapping:
                try:
                    with open(args.dump_mapping, 'w', encoding='utf-8') as f:
                        json.dump({str(k): v for k, v in cs_map.items()}, f, indent=2, ensure_ascii=False)
                    if args.verbose:
                        print(f"Dumped mapping to {args.dump_mapping}")
                except Exception as e:
                    print(f"Warning: failed to dump mapping: {e}")
            elif args.verbose:
                print(f"Loaded opcode mapping from crystalserver: {len(args.opcode_map)} entries")
        # Load server->client mapping too
        srv_map = load_server_opcode_map_from_crystalserver(args.mapping_source, verbose=args.verbose)
        if srv_map:
            args.server_opcode_map = srv_map
            if args.dump_mapping:
                try:
                    base, ext = os.path.splitext(args.dump_mapping)
                    outp = base + '_server' + (ext or '.json')
                    with open(outp, 'w', encoding='utf-8') as f:
                        json.dump({str(k): v for k, v in srv_map.items()}, f, indent=2, ensure_ascii=False)
                    if args.verbose:
                        print(f"Dumped server mapping to {outp}")
                except Exception as e:
                    print(f"Warning: failed to dump server mapping: {e}")
    if args.opcode_map is None:
        mapping_path = None
        default_map = os.path.join(os.path.dirname(__file__), 'New-folder--2-', 'enhanced_mapping.json')
        if os.path.isfile(default_map):
            mapping_path = default_map
        if mapping_path:
            try:
                with open(mapping_path, 'r', encoding='utf-8') as f:
                    mapping_json = json.load(f)
                opcode_map = {}
                # movement_opcodes
                for k, v in mapping_json.get('movement_opcodes', {}).items():
                    try:
                        code = int(k, 16)
                        name = v.get('direction')
                        if name:
                            opcode_map[code] = f"MOVE_{name.upper()}"
                    except Exception:
                        pass
                # creature_opcodes
                for k, v in mapping_json.get('creature_opcodes', {}).items():
                    try:
                        code = int(k, 16)
                        action = v.get('action')
                        if action:
                            opcode_map[code] = str(action)
                    except Exception:
                        pass
                args.opcode_map = opcode_map if opcode_map else None
                if args.verbose and args.opcode_map:
                    print(f"Loaded opcode mapping entries: {len(args.opcode_map)}")
            except Exception as e:
                print(f"Warning: failed to load opcode mapping: {e}")

    # handle interface listing/selection
    if args.list_ifaces:
        ifaces = list_interfaces(args.iface_type)
        print('\n'.join(ifaces))
        return
    if args.select:
        ifaces = list_interfaces(args.iface_type)
        if not ifaces:
            print('No interfaces found for type', args.iface_type)
            return
        print('Select interface:')
        for i, ifn in enumerate(ifaces):
            print(f"{i}: {ifn}")
        sel = input('Enter number: ')
        try:
            sel_i = int(sel)
            args.iface = ifaces[sel_i]
            print('Selected', args.iface)
        except Exception:
            print('Invalid selection')
            return

    if args.test:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        tmp.close()
        try:
            print(f"Generating test pcap at {tmp.name}")
            make_test_pcap(tmp.name)
            print("Parsing test pcap:")
            read_pcap(tmp.name, args)
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        return

    if args.pcap:
        read_pcap(args.pcap, args)
    elif args.iface:
        ports_info = args.ports if args.ports else [args.port]
        if not args.tibia_frame and any(p in (7171, 7172) for p in ports_info):
            args.tibia_frame = True
            args._auto_tibia_frame = True
        # Guidance for common Tibia ports
        ports_info = args.ports if args.ports else [args.port]
        if args.verbose or getattr(args, '_auto_tibia_frame', False):
            if any(p == 7172 for p in ports_info):
                print('[hint] login traffic detected (port 7172); Tibia frame parsing enabled automatically.')
            if any(p == 7171 for p in ports_info):
                if args.xtea_key_bytes is None:
                    print('[hint] game traffic (port 7171) is XTEA-encrypted. Provide --xtea-key <32hex> or use GUI scan to decrypt; displaying raw bytes otherwise.')
                else:
                    print('[hint] game traffic (port 7171) with provided XTEA key.')
        if getattr(args, '_auto_tibia_frame', False) and args.verbose:
            print('[hint] Tibia frame parsing was auto-enabled for known Tibia ports.')
        # Attempt to load mapping in CLI path as well
        if getattr(args, 'opcode_map', None) is None:
            args.opcode_map = _load_default_opcode_mapping(verbose=args.verbose)
        live_sniff(args)
    else:
        print("Provide --pcap <file> or --iface <interface>. Use --help for options.")


if __name__ == '__main__':
    main()
