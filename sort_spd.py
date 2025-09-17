#!/usr/bin/env python3
# spd_organizer.py
# Scan a directory for DDR2/DDR3/DDR4 SPD blocks, find HP HPT tags,
# move/rename dumps into a clean structure, extract multi-SPD files,
# keep a SQLite DB, and (optionally) generate an index.html.
# Now catalogs SPDs regardless of checksum validity and records stored vs computed CRC(s).

import argparse, os, sys, shutil, json, sqlite3, hashlib, time, html, re
from collections import defaultdict
from datetime import datetime, UTC
from typing import List, Optional, Tuple
import shlex, subprocess, tempfile

# --- New Import from hp_smartmemory_ident ---
# Assuming hp_smartmemory_ident.py is in the same directory or on the python path
try:
    from hp_smartmemory_ident import load_registry, u32, inv_mod_2p32, digits_to_u32_pn
except ImportError:
    sys.stderr.write("[WARN] hp_smartmemory_ident.py not found. HPT validation will be disabled.\n")
    load_registry = u32 = inv_mod_2p32 = digits_to_u32_pn = None


def json_sibling_path(spd_path: str) -> str:
    base, ext = os.path.splitext(spd_path)
    return (base + ".json") if base.endswith(".spd") else (base + ".spd.json")

def _is_valid_json_file(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except Exception:
        return False

def ensure_spd_json(spd_tool: str, spd_path: str, json_path: str,
                    extra_args: str = "", verbose: bool = False) -> bool:
    """
    Primary (robust): get JSON on stdout and write it ourselves:
        python spd_tool.py dump --spd <spd_path> --json - [extra_args]
    Fallback: ask tool to write the file itself (if it truly supports it):
        python spd_tool.py dump --spd <spd_path> --json <json_path> [extra_args]
    """
    try:
        need = (not os.path.exists(json_path) or
                os.path.getmtime(json_path) < os.path.getmtime(spd_path))
        if not need:
            return True

        os.makedirs(os.path.dirname(json_path), exist_ok=True)

        # --- PRIMARY: stdout JSON
        cmd = [sys.executable, spd_tool, "dump", "--spd", spd_path, "--json", "-"]
        if extra_args.strip():
            cmd += shlex.split(extra_args)
        if verbose:
            sys.stderr.write(f"[SPD-TOOL] {' '.join(cmd)}\n")

        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        txt = out.decode(errors="ignore").strip()

        # Try to parse as JSON; if there is any log noise, strip to JSON region.
        parsed = None
        try:
            parsed = json.loads(txt)
        except Exception:
            s1, e1 = txt.find("{"), txt.rfind("}")
            s2, e2 = txt.find("["), txt.rfind("]")
            span = None
            if s1 != -1 and e1 > s1: span = (s1, e1+1)
            if s2 != -1 and e2 > s2 and (span is None or (e2 - s2) > (span[1]-span[0])):
                span = (s2, e2+1)
            if span:
                try:
                    parsed = json.loads(txt[span[0]:span[1]])
                except Exception:
                    parsed = None

        if parsed is not None:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2, ensure_ascii=False)
            return True

        # --- FALLBACK: ask tool to write the file (only if it truly writes JSON)
        if verbose:
            sys.stderr.write("[SPD-TOOL] stdout did not contain valid JSON; trying file mode.\n")

        cmd = [sys.executable, spd_tool, "dump", "--spd", spd_path, "--json", json_path]
        if extra_args.strip():
            cmd += shlex.split(extra_args)
        if verbose:
            sys.stderr.write(f"[SPD-TOOL-FILE] {' '.join(cmd)}\n")

        res = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if verbose and res.stdout:
            sys.stderr.write(res.stdout.decode(errors="ignore"))

        # Validate file mode actually produced JSON
        if os.path.exists(json_path) and _is_valid_json_file(json_path):
            return True

        sys.stderr.write(f"[WARN] No valid JSON produced for {spd_path}. "
                         f"File contents may be status text.\n")
        return False

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"[WARN] spd_tool failed for {spd_path}:\n{e.output.decode(errors='ignore')}\n")
    except Exception as e:
        sys.stderr.write(f"[WARN] Could not create JSON for {spd_path}: {e}\n")
    return False


# ---------------------- SPD constants ----------------------
SPD128 = 128
SPD256 = 256
SPD512 = 512
MEM_SDR  = 0x04  # SDR SDRAM
MEM_DDR1 = 0x07  # DDR (aka DDR1)
MEM_DDR2 = 0x08
MEM_DDR3 = 0x0B
MEM_DDR4 = 0x0C
MEM_TYPES = {MEM_SDR: "SDR", MEM_DDR1: "DDR", MEM_DDR2: "DDR2", MEM_DDR3: "DDR3", MEM_DDR4: "DDR4"}

# --- 8-bit SPD checksums (legacy base at 63, optional ext at 95) ---
def checksum8(data: bytes) -> int:
    return sum(data) & 0xFF

# CRC-8 (polynomial 0x07) used by SDR/DDR SPD
def crc8_jedec(data: bytes, init: int = 0x00) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else ((crc << 1) & 0xFF)
    return crc

# ---------------------- CRC helpers ------------------------
def crc16_xmodem(data: bytes, init: int = 0x0000) -> int:
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def le16(b: bytes, off: int) -> int:
    return b[off] | (b[off+1] << 8)

# ---------------------- Utility helpers --------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_name(s: str, maxlen: int = 80) -> str:
    s = s.strip().replace("\x00", "")
    s = "".join(ch if ch.isalnum() or ch in "._-+()[]{} " else "_" for ch in s)
    s = "_".join(s.split())
    return s[:maxlen] if len(s) > maxlen else s

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def vendor_from_id(bank: int, code: int) -> str:
    return f"JEDEC(b{bank:02X},c{code:02X})"

def looks_like_legacy_base(block: bytes) -> bool:
    # Accept 128B or 256B images for SDR/DDR1 base block
    return len(block) in (SPD128, SPD256)

def looks_like_sdr(block: bytes) -> bool:
    return len(block) in (SPD128, SPD256) and block[2] == MEM_SDR

def looks_like_ddr1(block: bytes) -> bool:
    return looks_like_legacy_base(block) and block[2] == MEM_DDR1

def legacy_crc_pair(block: bytes) -> tuple[int|None, int|None, int|None, int|None, str]:
    """
    Return (stored_base8, computed_base8, stored_ext8, computed_ext8, status)
    status is:
      - 'ok'     if base (and ext if present) match
      - 'bad'    if base mismatches (or ext present and mismatches)
      - 'weak'   if base matches but ext region absent (len<96)
    """
    if not looks_like_legacy_base(block):
        return (None, None, None, None, "n/a")

    stored_base = block[63]
    computed_base = checksum8(block[0:63])  # bytes 0..62

    stored_ext = computed_ext = None
    status = "ok" if stored_base == computed_base else "bad"

    # Optional extension (64..94 -> byte 95)
    if len(block) >= 96:
        stored_ext = block[95]
        computed_ext = checksum8(block[64:95])  # bytes 64..94
        if status == "ok":
            status = "ok" if stored_ext == computed_ext else "bad"
    else:
        if status == "ok":
            status = "weak"

    return (stored_base, computed_base, stored_ext, computed_ext, status)

def parse_legacy_common(block: bytes, mem_type_label: str) -> dict:
    """
    Heuristic field map used by many SDR/DDR1 modules:
      - JEDEC Mfg ID (bank, code) at 64,65
      - Part Number ASCII at 73..90 (18 bytes)
      - Mfg week/year at 93,94
      - Serial (LE) at 95..98
    These are common but not universal; we treat as best-effort.
    """
    bank = block[64] if len(block) > 64 else 0
    code = block[65] if len(block) > 65 else 0
    pn = ""
    if len(block) >= 91:
        pn = block[73:91].rstrip(b"\x00").decode("ascii", errors="replace")
    wk = block[93] if len(block) > 93 else 0
    yr_raw = block[94] if len(block) > 94 else 0
    # Year heuristic: many modules store YY with 2000+; fall back if tiny
    yr = 2000 + yr_raw if yr_raw < 100 else int(yr_raw)
    serial = 0
    if len(block) >= 99:
        serial = int.from_bytes(block[95:99], 'little')

    sb, cb, se, ce, st = legacy_crc_pair(block)

    meta = {
        "mem_type": mem_type_label,
        "serial_u32_le": serial,
        "mfg_week": wk, "mfg_year": yr,
        "part_number_str": pn,
        "mfg_id_bank": bank, "mfg_id_code": code,
        "mfg_id_str": vendor_from_id(bank, code),
        "crc_status": st,
        # Store 8-bit checksums in the DDR3 fields to reuse schema/HTML:
        "stored_crc": sb,       # 8-bit base
        "computed_crc": cb,     # 8-bit base
        "stored_crc_base": None,    # unused for legacy
        "computed_crc_base": None,  # unused for legacy
        "stored_crc_ext": se,       # 8-bit ext (optional)
        "computed_crc_ext": ce,     # 8-bit ext (optional)
    }
    return meta

def parse_sdr(block: bytes) -> dict:
    bank, code = (block[64], block[65]) if len(block) > 65 else (0, 0)
    pn = block[73:91].rstrip(b"\x00").decode("ascii", errors="replace") if len(block) >= 91 else ""
    serial = int.from_bytes(block[95:99], "little", signed=False) if len(block) >= 99 else 0

    s_base = block[63]
    c_base = checksum8(block[0:63])

    ext_region = block[64:95]
    has_ext_payload = any(b != 0x00 for b in ext_region)
    s_ext = block[95] if len(block) > 95 else 0
    c_ext = checksum8(ext_region) if has_ext_payload else None

    base_ok = (s_base == c_base)
    ext_ok  = True if not has_ext_payload else (s_ext == c_ext)
    status  = "ok" if (base_ok and ext_ok) else "bad"

    return {
        "mem_type": "SDR",
        "serial_u32_le": serial,
        "part_number_str": pn or "Unknown",
        "mfg_id_bank": bank, "mfg_id_code": code,
        "mfg_id_str": vendor_from_id(bank, code),
        "crc_status": status,
        "stored_crc": s_base,
        "computed_crc": c_base,
        "stored_crc_ext": s_ext if has_ext_payload else None,
        "computed_crc_ext": c_ext if has_ext_payload else None,
    }

def parse_ddr1(block: bytes) -> dict:
    return parse_legacy_common(block, "DDR")


# ---------------------- DDR3 parse & CRCs ------------------
def looks_like_ddr3(block: bytes) -> bool:
    return len(block) in (SPD128, SPD256) and block[2] == MEM_DDR3 and (0x10 <= block[1] <= 0x13)

def ddr3_crc_pair(block: bytes) -> tuple[int|None, int|None, str]:
    """Return (stored_crc, computed_crc, status) for DDR3 (or (None,None,'n/a') if not applicable)."""
    if not looks_like_ddr3(block):
        return (None, None, "n/a")
    stored = le16(block, 126)
    computed = crc16_xmodem(block[0:117])
    status = "ok" if stored == computed else "bad"
    return (stored, computed, status)

def parse_ddr3(block: bytes) -> dict:
    serial = int.from_bytes(block[122:126], 'little')
    wk, yr = block[120], 2000 + (block[121] & 0xFF)
    pn = ""
    if len(block) >= 146:
        pn = block[128:146].rstrip(b"\x00").decode("ascii", errors="replace")
    bank, code = block[117], block[118]
    stored, computed, status = ddr3_crc_pair(block)
    return {
        "mem_type": "DDR3",
        "serial_u32_le": serial,
        "mfg_week": wk, "mfg_year": yr,
        "part_number_str": pn,
        "mfg_id_bank": bank, "mfg_id_code": code,
        "mfg_id_str": vendor_from_id(bank, code),
        "crc_status": status,
        "stored_crc": stored,
        "computed_crc": computed,
    }

# ---------------------- DDR4 parse & CRCs ------------------
def looks_like_ddr4(block: bytes) -> bool:
    return len(block) == SPD512 and block[2] == MEM_DDR4

def ddr4_crc_info(block: bytes) -> tuple[int|None,int|None,int|None,int|None,str]:
    """
    Return (stored_base, computed_base, stored_ext, computed_ext, status)
    status is "ok" only if both segments match; "bad" otherwise; "n/a" if not DDR4.
    """
    if not looks_like_ddr4(block):
        return (None, None, None, None, "n/a")
    stored_base = le16(block, 126)
    stored_ext  = le16(block, 254)
    comp_base   = crc16_xmodem(block[0:126])
    comp_ext    = crc16_xmodem(block[128:254])
    status = "ok" if (stored_base == comp_base and stored_ext == comp_ext) else "bad"
    return (stored_base, comp_base, stored_ext, comp_ext, status)

def parse_ddr4(block: bytes) -> dict:
    bank, code = block[320], block[321]
    pn = block[329:349].rstrip(b"\x00").decode("ascii", errors="replace")
    serial = int.from_bytes(block[325:329], 'little')
    s_b, c_b, s_e, c_e, st = ddr4_crc_info(block)
    return {
        "mem_type": "DDR4",
        "serial_u32_le": serial,
        "part_number_str": pn,
        "mfg_id_bank": bank, "mfg_id_code": code,
        "mfg_id_str": vendor_from_id(bank, code),
        "crc_status": st,
        "stored_crc_base": s_b, "computed_crc_base": c_b,
        "stored_crc_ext":  s_e, "computed_crc_ext":  c_e,
    }

# ---------------------- DDR2 (heuristic) -------------------
def looks_like_ddr2_spd(block: bytes) -> bool:
    return len(block) == SPD256 and block[2] == MEM_DDR2

def parse_ddr2(block: bytes) -> dict:
    bank, code = block[117], block[118]
    pn = block[128:146].rstrip(b"\x00").decode("ascii", errors="replace")
    if not pn:
        pn = block[73:91].rstrip(b"\x00").decode("ascii", errors="replace")
    serial = int.from_bytes(block[122:126], 'little')
    return {
        "mem_type": "DDR2",
        "serial_u32_le": serial,
        "part_number_str": pn,
        "mfg_id_bank": bank, "mfg_id_code": code,
        "mfg_id_str": vendor_from_id(bank, code),
        "crc_status": "weak_check",
    }

# ---------------------- HP HPT tag -------------------------
def extract_hp_hpt(block: bytes):
    """
    Finds the 'HPT' prefix and extracts the 4-byte code that follows
    the 4-byte tag area (e.g., 'HPT ' or 'HPT\x00').
    """
    tag_prefix = b"HPT"
    idx = block.find(tag_prefix)

    if idx < 0 or idx + 8 > len(block):
        return None

    hpt_bytes = block[idx + 4 : idx + 8]
    hpt = int.from_bytes(hpt_bytes, 'big')

    return {
        "hpt_tag_offset_in_spd": idx,
        "hpt_code_u32": hpt,
        "hpt_code_hex": f"0x{hpt:08X}"
    }

# --- New function for HPT validation ---
def validate_hpt(registry: dict, part_number: str, serial: int, hpt: int) -> str:
    """Validates an HPT code against the registry, returns a status string."""
    if not all([registry, part_number, hpt, u32, digits_to_u32_pn]):
        return "n/a"
    if not hpt:
        return "n/a"

    try:
        pn_u32 = digits_to_u32_pn(part_number)
        key = f"0x{pn_u32:08X}"
        fam = registry.get(key)
        if not fam:
            return "unknown_pn"

        A = int(fam["A"], 16)
        B = int(fam["B"], 16)
        K = int(fam["K"], 16)
        
        if u32(A * serial + B * hpt) == K:
            return "valid"
        else:
            return "invalid"
    except Exception:
        return "error"


# ---------------------- Scanning logic ---------------------
def scan_windows(data: bytes, size: int, step: int):
    end = len(data) - size + 1
    for off in range(0, max(0, end), step):
        yield off, data[off:off+size]

def scan_file_for_spd(path: str, step: int) -> List[dict]:
    results = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write(f"[WARN] Could not read {path}: {e}\n")
        return results

    n = len(data)

    # DDR4 (512B)
    for off, block in scan_windows(data, SPD512, step):
        if looks_like_ddr4(block):
            meta = parse_ddr4(block)
            hpt = extract_hp_hpt(block)
            if hpt: meta.update(hpt)
            results.append({"file": path, "file_offset": off, "spd_size": SPD512, "raw": block, **meta})

    # 256B windows: DDR3, DDR2, DDR1, SDR (in that order)
    for off, block in scan_windows(data, SPD256, step):
        if looks_like_ddr3(block):
            meta = parse_ddr3(block)
        elif looks_like_ddr2_spd(block):
            meta = parse_ddr2(block)
        elif looks_like_ddr1(block):
            meta = parse_ddr1(block)
        elif looks_like_sdr(block):
            meta = parse_sdr(block)
        else:
            continue
        hpt = extract_hp_hpt(block)
        if hpt: meta.update(hpt)
        results.append({"file": path, "file_offset": off, "spd_size": SPD256, "raw": block, **meta})

    # 128B windows: DDR3, DDR1, SDR (avoid duplicates if larger blocks exist)
    if 128 <= n < 256:
        for off, block in scan_windows(data, SPD128, step):
            if looks_like_ddr3(block):
                meta = parse_ddr3(block)
            elif looks_like_ddr1(block):
                meta = parse_ddr1(block)
            elif looks_like_sdr(block):
                meta = parse_sdr(block)
            else:
                continue
            hpt = extract_hp_hpt(block)
            if hpt: meta.update(hpt)
            results.append({"file": path, "file_offset": off, "spd_size": SPD128, "raw": block, **meta})

    return results


def walk_paths(root: str, recursive: bool):
    if os.path.isfile(root):
        yield root
        return
    for base, dirs, files in os.walk(root):
        for fn in files:
            yield os.path.join(base, fn)
        if not recursive:
            break

# ---------------------- SQLite catalog --------------------
DDL = """
CREATE TABLE IF NOT EXISTS spd (
    id INTEGER PRIMARY KEY,
    added_ts INTEGER NOT NULL,
    src_path TEXT NOT NULL,
    src_sha256 TEXT NOT NULL,
    file_offset INTEGER NOT NULL,
    spd_size INTEGER NOT NULL,
    mem_type TEXT NOT NULL,
    vendor TEXT,
    vendor_bank INTEGER,
    vendor_code INTEGER,
    part_number TEXT,
    serial_u32 INTEGER,
    crc_status TEXT,
    -- DDR3 CRCs
    stored_crc INTEGER,
    computed_crc INTEGER,
    -- DDR4 CRCs
    stored_crc_base INTEGER,
    computed_crc_base INTEGER,
    stored_crc_ext INTEGER,
    computed_crc_ext INTEGER,
    hpt_hex TEXT,
    hpt_u32 INTEGER,
    hpt_status TEXT, -- New column for HPT validation status
    computed_hpt_u32 INTEGER, -- New column for computed HPT
    hp_part_number TEXT, -- New column for resolved HP P/N
    dest_path TEXT,
    json_path TEXT,
    spd_sha256 TEXT NOT NULL,
    UNIQUE(spd_sha256)
);
CREATE INDEX IF NOT EXISTS idx_mem_vendor ON spd(mem_type, vendor);
CREATE INDEX IF NOT EXISTS idx_serial ON spd(serial_u32);
CREATE INDEX IF NOT EXISTS idx_hpt ON spd(hpt_u32);
"""

def db_connect(path: str):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    for stmt in DDL.strip().split(";"):
        s = stmt.strip()
        if s: conn.execute(s)
    return conn

def db_migrate(conn: sqlite3.Connection):
    # Add missing columns if the DB pre-dates CRC fields, etc.
    # (SQLite ALTER TABLE ADD COLUMN is safe and idempotent if we check first.)
    cur = conn.execute("PRAGMA table_info(spd)")
    cols = {row[1] for row in cur.fetchall()}  # column names

    def add(colname: str, decl: str):
        if colname not in cols:
            conn.execute(f"ALTER TABLE spd ADD COLUMN {colname} {decl}")

    # CRC-related columns:
    add("stored_crc", "INTEGER")
    add("computed_crc", "INTEGER")
    add("stored_crc_base", "INTEGER")
    add("computed_crc_base", "INTEGER")
    add("stored_crc_ext", "INTEGER")
    add("computed_crc_ext", "INTEGER")
    add("json_path", "TEXT")
    add("hpt_status", "TEXT") # Add the new column to the migration
    add("computed_hpt_u32", "INTEGER") # Add the new column for computed HPT
    add("hp_part_number", "TEXT")

    # (No-op if they already exist)
    conn.commit()

def db_upsert(conn, row: dict):
    cols = ("added_ts","src_path","src_sha256","file_offset","spd_size","mem_type",
            "vendor","vendor_bank","vendor_code","part_number","serial_u32",
            "crc_status","stored_crc","computed_crc",
            "stored_crc_base","computed_crc_base","stored_crc_ext","computed_crc_ext",
            "hpt_hex","hpt_u32", "hpt_status", "computed_hpt_u32", "hp_part_number", "dest_path","json_path","spd_sha256")
    vals = tuple(row.get(c) for c in cols)

    # On conflict, refresh ALL mutable columns so old rows get backfilled
    update_cols = [c for c in cols if c not in ("spd_sha256",)]  # keep the unique key
    set_clause = ", ".join(f"{c}=excluded.{c}" for c in update_cols)

    conn.execute(f"""
        INSERT INTO spd ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})
        ON CONFLICT(spd_sha256) DO UPDATE SET
          {set_clause}
    """, vals)


# ---------------------- Organizing / moving ---------------
def dest_rel_path(mem_type: str, vendor: str, part_number: str, serial_hex: str, hpt_hex: str, suffix: str):
    folder = os.path.join(mem_type, safe_name(vendor or "Unknown"), safe_name(part_number or "Unknown"))
    base = f"{safe_name(part_number or 'Module')}__{serial_hex}"
    if hpt_hex:
        base += f"__{hpt_hex}"
    return os.path.join(folder, f"{base}.{suffix}")

def ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def write_index_html(out_dir: str, rows: List[dict], html_path: str):
    rows_sorted = sorted(rows, key=lambda r: (r["mem_type"], r["vendor"], r["part_number"], r["serial_u32"]))
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("<!doctype html><html><head><meta charset='utf-8'>"
                "<title>SPD Index</title>"
                "<style>body{font-family:system-ui,Arial,sans-serif}"
                "table{border-collapse:collapse;width:100%}"
                "th,td{border:1px solid #ddd;padding:6px}th{background:#f3f3f3;text-align:left}"
                "code{font-family:ui-monospace,Consolas,monospace}</style>"
                "</head><body>")
        f.write("""
                <style>
                #specsModal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:center;justify-content:center;z-index:9999}
                #specsBox{background:#fff;max-width:1000px;width:95%;max-height:85vh;overflow:auto;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
                #specsHdr{display:flex;gap:8px;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid #eee;position:sticky;top:0;background:#fff;z-index:1}
                #specsBody{padding:14px}
                #specsBody pre{white-space:pre-wrap;word-break:break-word;border:1px dashed #ddd;padding:8px;border-radius:8px;background:#fafafa}
                .viewbtn,.chip{padding:4px 8px;border:1px solid #888;background:#f8f8f8;border-radius:6px;cursor:pointer}
                .viewbtn:hover{background:#eee}
                .chip{font-size:.85em}
                .sec{margin:14px 0;border:1px solid #eee;border-radius:8px}
                .sec h3{margin:0;padding:8px 12px;border-bottom:1px solid #eee;background:#f7f7f7}
                .kv{display:grid;grid-template-columns:220px 1fr;gap:6px 12px;padding:10px 12px}
                .kv div.key{color:#555}
                .kv code{font-family:ui-monospace,Consolas,monospace}
                .bad{color:#b00020;font-weight:600}
                .ok{color:#0a7f3f;font-weight:600}
                .mono{font-family:ui-monospace,Consolas,monospace}
                .small{font-size:.92em;color:#666}
                </style>

                <div id="specsModal">
                <div id="specsBox">
                    <div id="specsHdr">
                    <div style="display:flex;gap:8px;align-items:center">
                        <strong>SPD Specs</strong>
                        <span id="specsMeta" class="small mono"></span>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center">
                        <button id="specsToggle" class="chip">Raw JSON</button>
                        <button id="specsClose" class="viewbtn">Close</button>
                    </div>
                    </div>
                    <div id="specsBody">
                    <div id="specsFormatted"></div>
                    <pre id="specsRaw" style="display:none">Loading…</pre>
                    </div>
                </div>
                </div>

                <script>

                function isPlainObject(v){ return v && typeof v === "object" && !Array.isArray(v); }
                function isPrimitive(v){ return v===null || (typeof v!=="object" && typeof v!=="function"); }

                (function(){
                const modal = document.getElementById('specsModal');
                const btnClose = document.getElementById('specsClose');
                const btnToggle = document.getElementById('specsToggle');
                const rawPre = document.getElementById('specsRaw');
                const formatted = document.getElementById('specsFormatted');
                const meta = document.getElementById('specsMeta');
                let showRaw = false;

                function show(){ modal.style.display='flex'; }
                function hide(){ modal.style.display='none'; rawPre.textContent=''; formatted.innerHTML=''; meta.textContent=''; showRaw=false; updateToggle(); }
                function updateToggle(){ btnToggle.textContent = showRaw ? "Formatted" : "Raw JSON"; rawPre.style.display = showRaw ? "block" : "none"; formatted.style.display = showRaw ? "none" : "block"; }

                btnClose.addEventListener('click', hide);
                modal.addEventListener('click', (e)=>{ if(e.target===modal) hide(); });
                btnToggle.addEventListener('click', ()=>{ showRaw = !showRaw; updateToggle(); });

                // Heuristics & helpers
                const secTitles = [
                    "SPD General","Module Configuration","SDRAM Addressing",
                    "SDRAM Optional Features","SDRAM Thermal & Refresh Features",
                    "Module Mechanical Details","Registered/Buffered Info",
                    "JEDEC Timing Parameters (ns)","Timings in Clocks (at tCKmin)",
                    "Standard JEDEC Down-clock Profiles","Manufacturing Information",
                    "HP SmartMemory Information","SPD CRC Verification","Undecoded/Reserved Gaps"
                ];

                function fmtHex(val, width=2){
                    if (val === null || val === undefined) return "";
                        if (typeof val === "number") {
                            const w = Math.max(1, width|0);
                            const hex = (val >>> 0).toString(16).toUpperCase().padStart(w, "0");
                            return "0x" + hex;
                        }
                        if (typeof val === "string" && /^[0-9a-fA-F]+$/.test(val) && val.length % 2 === 0 && val.length <= 64) {
                            return "0x" + val.toUpperCase();
                        }
                    return String(val);
                }

                function labelize(k){
                    // prettify typical JSON keys
                    return k.replace(/_/g," ")
                            .replace(/\bids?\b/gi, m => m.toUpperCase())
                            .replace(/\bspd\b/gi, "SPD")
                            .replace(/\bhpt\b/gi, "HPT")
                            .replace(/\bcrc\b/gi, "CRC")
                            .replace(/\bjedec\b/gi, "JEDEC")
                            .replace(/\bdram\b/gi, "DRAM")
                            .replace(/\bmfg\b/gi, "Mfg")
                            .replace(/\btc[kx]\b/gi, m => m.toUpperCase())
                            .replace(/\bns\b/gi, "ns")
                            .replace(/\bcl\b/gi, "CL")
                            .replace(/\\bx(\\d+)\\b/gi, "x$1")
                            .replace(/\bpc[2345]-?/i, m => m.toUpperCase());
                }

                function fmtVal(key, val){
                    // Hex-ish keys show in hex code
                    if (/(_hex|_u32|_crc|crc_|_id|_code|_offset|serial)/i.test(key) && (typeof val === "number" || typeof val === "string")) {
                        return "<code>" + fmtHex(val, 8) + "</code>";
                    }
                    if (isPrimitive(val)) return String(val);
                    if (Array.isArray(val)) return renderArray(val);
                    if (isPlainObject(val)) return renderKVTable(val);
                    return String(val);
                }

                function renderArray(arr){
                    if (arr.length === 0) return "[]";
                    const allPrimitive = arr.every(isPrimitive);
                    const allObjects   = arr.every(isPlainObject);
                    if (allPrimitive) {
                        return "<code>" + arr.join(", ") + "</code>";
                    }
                    if (allObjects) {
                        // Build a table with union of keys
                        const keySet = new Set();
                        arr.forEach(o => Object.keys(o).forEach(k => keySet.add(k)));
                        const keys = Array.from(keySet);
                        const head = keys.map(k => `<th>${labelize(k)}</th>`).join("");
                        const rows = arr.map(o => {
                        const tds = keys.map(k => `<td>${fmtVal(k, o[k] ?? "")}</td>`).join("");
                        return `<tr>${tds}</tr>`;
                        }).join("");
                        return `<div style="overflow:auto"><table class="kv" style="display:table;width:auto">
                        <thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>`;
                    }
                    // Mixed types—fallback: list each item with JSON
                    const items = arr.map(v => `<li>${isPlainObject(v) ? renderKVTable(v) : "<code>"+String(v)+"</code>"}</li>`).join("");
                    return `<ul>${items}</ul>`;
                }

                function renderKVTable(obj){
                const rows = Object.keys(obj).map(k => {
                    return `<div class="key">${labelize(k)}</div><div class="val">${fmtVal(k, obj[k])}</div>`;
                }).join("");
                return `<div class="kv">${rows}</div>`;
                }

                function asKV(key, val){
                const k = labelize(key);
                return `<div class="key">${k}</div><div class="val">${fmtVal(key, val)}</div>`;
                }

                function renderSection(title, content){
                    return `<div class="sec"><h3>${title}</h3>${content}</div>`;
                }

                function sectionFromFlatObject(obj){
                    return renderSection("Details", renderKVTable(obj));
                }

                function renderTop(decoded){
                    let out = "";
                    // If structured by known headings (your spd_tool does this), show them in order:
                    let shownAny = false;
                    for (const sec of secTitles) {
                    if (decoded[sec]) {
                        out += renderSection(sec, renderKVTable(decoded[sec]));
                        shownAny = true;
                    }
                    }
                    // Show leftover keys (not in the known headings) in a final section
                    const leftovers = {};
                    if (typeof decoded === "object") {
                    for (const k of Object.keys(decoded)) {
                        if (!secTitles.includes(k)) leftovers[k] = decoded[k];
                    }
                    }
                    if (!shownAny) {
                    // No known headings → try to present everything nicely
                    if (typeof decoded === "object" && !Array.isArray(decoded)) {
                        out += sectionFromFlatObject(decoded);
                    } else {
                        out += `<pre class="mono">${escapeHTML(JSON.stringify(decoded,null,2))}</pre>`;
                    }
                    } else if (Object.keys(leftovers).length) {
                    out += renderSection("Other", renderKVTable(leftovers));
                    }
                    return out;
                }

                function escapeHTML(s){ return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

                async function viewJson(jsonPath, rowMeta){
                    try{
                    formatted.innerHTML = "";
                    rawPre.textContent = "Loading…";
                    show();
                    const resp = await fetch(jsonPath);
                    if(!resp.ok){ rawPre.textContent = "Failed to load JSON: " + resp.status; showRaw=true; updateToggle(); return; }
                    const txt = await resp.text();
                    rawPre.textContent = txt;
                    let decoded;
                    try { decoded = JSON.parse(txt); }
                    catch (e) { showRaw = true; updateToggle(); return; }

                    // Populate header meta (nice to show at top)
                    meta.textContent = rowMeta || "";

                    // Build formatted view
                    formatted.innerHTML = renderTop(decoded);
                    showRaw = false;
                    updateToggle();
                    }catch(err){
                    rawPre.textContent = "Error: " + err;
                    showRaw = true;
                    updateToggle();
                    }
                }

                // Wire up table buttons
                document.addEventListener('click', (e) => {
                    const btn = e.target.closest('.viewbtn[data-json]');
                    if(!btn) return;
                    const jsonPath = btn.getAttribute('data-json');
                    const rowMeta = btn.getAttribute('data-meta') || "";
                    viewJson(jsonPath, rowMeta);
                });
                })();
                </script>

                """)

        f.write(f"<h1>SPD Catalog</h1><p>Generated {now}</p>")
        f.write("<table><tr>"
                "<th>Type</th><th>Vendor</th><th>Part Number</th><th>HP P/N</th><th>Serial</th>"
                "<th>HPT</th><th>HPT Status</th><th>Computed HPT</th><th>CRC Status</th><th>Stored CRC</th><th>Computed CRC</th>"
                "<th>File</th><th>View Specs</th></tr>")
        for r in rows_sorted:
            vendor = html.escape(r.get("vendor","") or "")
            pn = html.escape(r.get("part_number","") or "")
            hp_pn = html.escape(r.get("hp_part_number", ""))
            serial = f"0x{(r.get('serial_u32') or 0):08X}"
            hpt = html.escape(r.get("hpt_hex") or "")
            hpt_status = html.escape(r.get("hpt_status", ""))
            computed_hpt = f"0x{(r.get('computed_hpt_u32') or 0):08X}" if r.get('computed_hpt_u32') is not None else ""
            crc_status = r.get("crc_status","")

            # Prefer DDR4 base CRCs; else DDR3/legacy single CRC8
            stored_crc = r.get("stored_crc_base")
            computed_crc = r.get("computed_crc_base")
            if stored_crc is None and computed_crc is None:
                stored_crc = r.get("stored_crc")
                computed_crc = r.get("computed_crc")

            def fmt_crc(v: object) -> str:
                if not isinstance(v, int):
                    return ""
                # Heuristic: legacy is 0..255 -> 2 digits; otherwise 4 digits
                return f"0x{v:02X}" if 0 <= v < 0x100 else f"0x{v:04X}"

            sc = fmt_crc(stored_crc)
            cc = fmt_crc(computed_crc)

            # Optional: also display extension CRCs if present (SDR/DDR)
            sc_ext = fmt_crc(r.get("stored_crc_ext"))
            cc_ext = fmt_crc(r.get("computed_crc_ext"))
            ext_cell = ""
            if sc_ext or cc_ext:
                ext_cell = f"<div>ext: <code>{sc_ext}</code> → <code>{cc_ext}</code></div>"

            rel = os.path.relpath(r.get("dest_path",""), os.path.dirname(html_path)).replace(os.sep, "/")
            link = html.escape(rel)

            json_rel = ""
            jp = r.get("json_path")
            if jp:
                json_rel = os.path.relpath(jp, os.path.dirname(html_path)).replace(os.sep, "/")

            meta_text = f"{r.get('mem_type','')} · {pn} · {serial}"
            view_btn = (f"<button class='viewbtn' data-json='{html.escape(json_rel)}' "
                        f"data-meta='{html.escape(meta_text)}'>View</button>"
                        if json_rel else "")

            f.write("<tr>"
                    f"<td>{r.get('mem_type','')}</td>"
                    f"<td>{vendor}</td>"
                    f"<td>{pn}</td>"
                    f"<td>{hp_pn}</td>"
                    f"<td><code>{serial}</code></td>"
                    f"<td><code>{hpt}</code></td>"
                    f"<td>{hpt_status}</td>"
                    f"<td><code>{computed_hpt}</code></td>"
                    f"<td>{html.escape(crc_status)}</td>"
                    f"<td><code>{sc}</code></td>"
                    f"<td><code>{cc}</code>{ext_cell}</td>"
                    f"<td><a href='{link}'>{link}</a></td>"
                    f"<td>{view_btn}</td>"
                    "</tr>")
            
        f.write("</table></body></html>")


# ---------------------- Main flow -------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Organize DDR2/DDR3/DDR4 SPD dumps: scan, detect HPT, move/rename, index to SQLite/HTML (CRC stored & computed)."
    )
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("-r", "--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--step", type=int, default=1, help="Sliding window step (default 1; try 16/32 for speed)")
    ap.add_argument("--out-root", required=True, help="Destination root folder for organized outputs")
    ap.add_argument("--db", default="spd_catalog.sqlite3", help="SQLite DB path")
    ap.add_argument("--html", help="Also write an index.html at the given path")
    ap.add_argument("--move-single", action="store_true",
                    help="If a source file contains exactly one SPD block, move/rename the ORIGINAL file into the structure. "
                         "Otherwise extract SPDs to .spd.bin and leave the original.")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--spd-tool", default="spd_tool.py",
                    help="Path to spd_tool.py (default: spd_tool.py on PATH)")
    ap.add_argument("--spd-tool-args", default="", 
                help='Extra args for spd_tool.py dump (e.g. "--programmer")')
    ap.add_argument("--hpt-registry", default="hp_families.json", help="Path to HP families JSON registry")
    args = ap.parse_args()

    out_root = os.path.abspath(args.out_root)
    os.makedirs(out_root, exist_ok=True)
    conn = db_connect(args.db)
    db_migrate(conn)

    hp_registry = load_registry(args.hpt_registry) if load_registry else {}
    # Create a reverse map from vendor P/N to HP P/N info
    hp_reverse_map = {}
    if hp_registry:
        for hp_pn_key, fam in hp_registry.items():
            for eq_pn in fam.get("equivalents", []):
                hp_reverse_map[eq_pn] = fam


    all_paths = list(walk_paths(args.path, args.recursive))
    added_rows = []
    processed_files = set()

    for p in all_paths:
        matches = scan_file_for_spd(p, args.step)
        if matches:
            processed_files.add(os.path.abspath(p))  # mark as having at least one SPD
        if not matches:
            continue

        

        move_original = (args.move_single and len(matches) == 1)
        src_hash = file_sha256(p) if move_original else None

        for idx, m in enumerate(matches):
            block = m.pop("raw")
            spd_hash = sha256_hex(block)
            # Optional: skip heavy rewrites if already in DB
            cur = conn.execute("SELECT 1 FROM spd WHERE spd_sha256=? LIMIT 1", (spd_hash,))
            already = cur.fetchone() is not None

            mem_type = m.get("mem_type")
            vendor = m.get("mfg_id_str")
            pn = m.get("part_number_str") or "Unknown"
            serial_u32 = m.get('serial_u32_le', 0)
            serial_hex = f"0x{serial_u32:08X}"
            hpt_u32 = m.get("hpt_code_u32")
            hpt_hex = m.get("hpt_code_hex","")

            # --- HPT Validation and Computation ---
            computed_hpt_u32 = None
            hpt_status = "n/a"
            hp_pn = ""
            if hp_reverse_map and pn in hp_reverse_map:
                fam = hp_reverse_map[pn]
                hp_pn = fam.get("name")
                if hp_pn:
                    try:
                        pn_u32 = digits_to_u32_pn(hp_pn)
                        key = f"0x{pn_u32:08X}"
                        fam = hp_registry.get(key)
                        if fam and all(k in fam for k in ["A", "B", "K"]):
                            A = int(fam["A"], 16)
                            B = int(fam["B"], 16)
                            K = int(fam["K"], 16)
                            if (B & 1) != 0:
                                invB = inv_mod_2p32(B)
                                computed_hpt_u32 = u32((u32(K) - u32(A * serial_u32)) * invB)

                                if hpt_u32:
                                    if hpt_u32 == computed_hpt_u32:
                                        hpt_status = "match"
                                    else:
                                        hpt_status = "mismatch"
                                else:
                                    hpt_status = "generated"

                    except Exception as e:
                        if args.verbose:
                            sys.stderr.write(f"[WARN] HPT computation failed for {pn}: {e}\n")


            # Decide destination
            if move_original:
                src_ext = os.path.splitext(p)[1].lstrip(".") or "bin"
                rel = dest_rel_path(mem_type, vendor, pn, serial_hex, hpt_hex, src_ext)
                dest = os.path.join(out_root, rel)
                if not os.path.exists(dest):
                    ensure_dir(dest)
                    base, ext = os.path.splitext(dest)
                    n = 1
                    while os.path.exists(dest):
                        dest = f"{base}__dup{n}{ext}"; n += 1
                    shutil.move(p, dest)
                src_path = p
                dest_path = dest
            else:
                rel = dest_rel_path(mem_type, vendor, pn, serial_hex, hpt_hex, "spd.bin")
                dest = os.path.join(out_root, rel)
                ensure_dir(dest)
                if not os.path.exists(dest):
                    with open(dest, "wb") as f:
                        f.write(block)
                src_path = p
                dest_path = dest

            json_path = json_sibling_path(dest_path)
            ensure_spd_json(args.spd_tool, dest_path, json_path,
                            extra_args=args.spd_tool_args, verbose=args.verbose)


            # CRC columns (DDR3/DDR4 variants)
            stored_crc = m.get("stored_crc")
            computed_crc = m.get("computed_crc")
            stored_crc_base = m.get("stored_crc_base")
            computed_crc_base = m.get("computed_crc_base")
            stored_crc_ext = m.get("stored_crc_ext")
            computed_crc_ext = m.get("computed_crc_ext")

            row = {
                "added_ts": int(time.time()),
                "src_path": os.path.abspath(src_path),
                "src_sha256": src_hash or "",
                "file_offset": m.get("file_offset", 0),
                "spd_size": m.get("spd_size", 0),
                "mem_type": mem_type,
                "vendor": vendor,
                "vendor_bank": int(m.get("mfg_id_bank", 0)),
                "vendor_code": int(m.get("mfg_id_code", 0)),
                "part_number": pn,
                "serial_u32": int(m.get("serial_u32_le", 0)),
                "crc_status": m.get("crc_status", ""),
                "stored_crc": stored_crc,
                "computed_crc": computed_crc,
                "stored_crc_base": stored_crc_base,
                "computed_crc_base": computed_crc_base,
                "stored_crc_ext": stored_crc_ext,
                "computed_crc_ext": computed_crc_ext,
                "hpt_hex": hpt_hex or "",
                "hpt_u32": hpt_u32,
                "hpt_status": hpt_status,
                "computed_hpt_u32": computed_hpt_u32,
                "hp_part_number": hp_pn,
                "dest_path": os.path.abspath(dest_path),
                "json_path": os.path.abspath(json_path),
                "spd_sha256": spd_hash,
            }
            db_upsert(conn, row)
            added_rows.append(row)

    conn.commit()
    conn.close()

    all_paths_abs = {os.path.abspath(p) for p in all_paths}
    files_no_spd = sorted(all_paths_abs - processed_files)

    # De-duplicate rows for HTML by SPD content (sha256)
    unique_rows, _seen = [], set()
    for r in added_rows:
        sig = r.get("spd_sha256")
        if not sig or sig in _seen:
            continue
        _seen.add(sig)
        unique_rows.append({
            "mem_type": r["mem_type"],
            "vendor": r["vendor"],
            "part_number": r["part_number"],
            "hp_part_number": r.get("hp_part_number"),
            "serial_u32": r["serial_u32"],
            "hpt_hex": r["hpt_hex"],
            "hpt_status": r["hpt_status"],
            "computed_hpt_u32": r.get("computed_hpt_u32"),
            "crc_status": r["crc_status"],
            "stored_crc": r.get("stored_crc"),
            "computed_crc": r.get("computed_crc"),
            "stored_crc_base": r.get("stored_crc_base"),
            "computed_crc_base": r.get("computed_crc_base"),
            "stored_crc_ext": r.get("stored_crc_ext"),
            "computed_crc_ext": r.get("computed_crc_ext"),
            "dest_path": r["dest_path"],
            "json_path": r.get("json_path"),
        })

    if args.html:
        write_index_html(out_root, unique_rows, args.html)

    print(f"\nProcessed {len(all_paths)} file(s).")
    print(f"Indexed {len(_seen)} unique SPD block(s).")
    if files_no_spd:
        print("Files with no SPD found:")
        for f in files_no_spd:
            print(f"  - {f}")
    else:
        print("All files contained at least one SPD (or were not scanned due to errors).")

if __name__ == "__main__":
    main()