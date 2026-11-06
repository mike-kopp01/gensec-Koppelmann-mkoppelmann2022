#!/usr/bin/env python3
"""
traffic_analyzer.py  --  offline pcap analyzer + HTML visualizer.

Coursework tool. Reads a classic libpcap (.pcap) capture, decodes
Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP from scratch (stdlib struct only),
aggregates statistics, and renders a self-contained HTML report with inline
SVG charts (no external libraries, works offline).

Analyzes capture FILES only - it does not sniff the network, so it needs no
privileges and cannot touch live traffic. Make a capture with
Wireshark/tcpdump first, then analyze it here.

Subcommands / usage
-------------------
    python traffic_analyzer.py make-sample
    python traffic_analyzer.py analyze samples/sample.pcap --html report.html
    python traffic_analyzer.py analyze capture.pcap --json --top 20
    python traffic_analyzer.py selftest

Stdlib only (Python 3.10+).
"""
from __future__ import annotations

import argparse
import html
import json
import os
import socket
import struct
import sys
import tempfile
from collections import Counter, defaultdict

IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 2: "IGMP", 89: "OSPF"}
WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 8080: "http-alt",
}


# ==========================================================================
# SECTION 1 - pcap file + protocol decoding
# ==========================================================================

class PcapError(Exception):
    pass


def _endian_and_scale(magic: bytes):
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">", 1e-6
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<", 1e-6
    if magic == b"\xa1\xb2\x3c\x4d":
        return ">", 1e-9
    if magic == b"\x4d\x3c\xb2\xa1":
        return "<", 1e-9
    raise PcapError("not a classic .pcap file (bad magic; pcapng not supported)")


def parse_pcap(path: str) -> tuple[list[dict], int]:
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise PcapError("file too short")
    endian, scale = _endian_and_scale(data[:4])
    _, _, _, _, _, _, linktype = struct.unpack_from(endian + "IHHiIII", data, 0)
    off, packets = 24, []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) < incl:
            break
        pkt = {"ts": ts_sec + ts_usec * scale, "length": orig}
        try:
            _decode_frame(frame, linktype, pkt)
        except Exception:
            pkt.setdefault("l3", "malformed")
        packets.append(pkt)
    return packets, linktype


def _decode_frame(frame: bytes, linktype: int, pkt: dict) -> None:
    if linktype == 1:                               # Ethernet
        if len(frame) < 14:
            pkt["l3"] = "short"
            return
        etype = struct.unpack_from(">H", frame, 12)[0]
        payload = frame[14:]
        if etype == 0x8100 and len(frame) >= 18:    # 802.1Q VLAN
            etype = struct.unpack_from(">H", frame, 16)[0]
            payload = frame[18:]
        if etype == 0x0800:
            _decode_ipv4(payload, pkt)
        elif etype == 0x86DD:
            _decode_ipv6(payload, pkt)
        elif etype == 0x0806:
            pkt["l3"] = "ARP"
        else:
            pkt["l3"] = f"0x{etype:04x}"
    elif linktype in (101, 12, 14):                 # raw IP
        ver = frame[0] >> 4 if frame else 0
        if ver == 4:
            _decode_ipv4(frame, pkt)
        elif ver == 6:
            _decode_ipv6(frame, pkt)
        else:
            pkt["l3"] = "raw?"
    else:
        pkt["l3"] = f"linktype{linktype}"


def _decode_ipv4(d: bytes, pkt: dict) -> None:
    if len(d) < 20:
        pkt["l3"] = "ipv4-short"
        return
    ihl = (d[0] & 0x0F) * 4
    pkt["l3"] = "IPv4"
    pkt["src_ip"] = socket.inet_ntoa(d[12:16])
    pkt["dst_ip"] = socket.inet_ntoa(d[16:20])
    _decode_l4(d[ihl:], d[9], pkt)


def _decode_ipv6(d: bytes, pkt: dict) -> None:
    if len(d) < 40:
        pkt["l3"] = "ipv6-short"
        return
    pkt["l3"] = "IPv6"
    pkt["src_ip"] = socket.inet_ntop(socket.AF_INET6, d[8:24])
    pkt["dst_ip"] = socket.inet_ntop(socket.AF_INET6, d[24:40])
    _decode_l4(d[40:], d[6], pkt)


def _decode_l4(d: bytes, proto: int, pkt: dict) -> None:
    pkt["l4"] = IP_PROTO.get(proto, f"proto{proto}")
    if proto in (6, 17) and len(d) >= 4:
        pkt["src_port"], pkt["dst_port"] = struct.unpack_from(">HH", d, 0)
        if proto == 6 and len(d) >= 14:
            pkt["tcp_flags"] = d[13] & 0x3F


# ==========================================================================
# SECTION 2 - aggregation
# ==========================================================================

def analyze(packets: list[dict], top: int = 10) -> dict:
    total_bytes = sum(p["length"] for p in packets)
    times = [p["ts"] for p in packets if p.get("ts")]
    duration = (max(times) - min(times)) if len(times) > 1 else 0.0

    l4, talkers, dst_ports, convos = Counter(), Counter(), Counter(), Counter()
    for p in packets:
        l4[p.get("l4") or p.get("l3") or "other"] += 1
        if p.get("src_ip"):
            talkers[p["src_ip"]] += p["length"]
        if "dst_port" in p:
            dst_ports[p["dst_port"]] += 1
        if p.get("src_ip") and p.get("dst_ip"):
            a, b = sorted((p["src_ip"], p["dst_ip"]))
            convos[(a, b)] += p["length"]

    buckets = defaultdict(int)
    if times:
        t0 = int(min(times))
        for p in packets:
            if p.get("ts"):
                buckets[int(p["ts"]) - t0] += 1
    timeline = [buckets.get(s, 0) for s in range(max(buckets) + 1)] if buckets else []

    def label_port(port):
        svc = WELL_KNOWN.get(port)
        return f"{port} ({svc})" if svc else str(port)

    return {
        "packets": len(packets), "bytes": total_bytes,
        "duration": round(duration, 3),
        "pps": round(len(packets) / duration, 1) if duration else 0,
        "protocols": l4.most_common(),
        "top_talkers": talkers.most_common(top),
        "top_ports": [(label_port(p), c) for p, c in dst_ports.most_common(top)],
        "top_convos": [(f"{a} <-> {b}", c) for (a, b), c in convos.most_common(top)],
        "timeline": timeline,
    }


def render_text(s: dict) -> str:
    out, bar = [], "=" * 60
    out += [bar, "  TRAFFIC ANALYSIS", bar,
            f"  packets   : {s['packets']}", f"  bytes     : {s['bytes']:,}",
            f"  duration  : {s['duration']} s   ({s['pps']} pkt/s)", bar]

    def section(title, rows, fmt=str):
        out.append(f"  {title}")
        if not rows:
            out.append("    (none)")
        for name, val in rows:
            out.append(f"    {str(name):<34}{fmt(val)}")
        out.append("")

    section("protocols (by packets)", s["protocols"])
    section("top talkers (by bytes out)", s["top_talkers"], lambda v: f"{v:,} B")
    section("top destination ports", s["top_ports"])
    section("top conversations (by bytes)", s["top_convos"], lambda v: f"{v:,} B")
    return "\n".join(out)


# ==========================================================================
# SECTION 3 - HTML / SVG visualizer (self-contained, offline)
# ==========================================================================

PROTO_COLOR = {"TCP": "#3b82f6", "UDP": "#10b981", "ICMP": "#f59e0b",
               "ICMPv6": "#f59e0b", "ARP": "#a855f7", "DNS": "#10b981"}
_PALETTE = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#a855f7",
            "#06b6d4", "#ec4899", "#84cc16", "#f97316", "#6366f1"]


def _bar_chart(rows, unit="", colorfn=None) -> str:
    if not rows:
        return "<p class='empty'>no data</p>"
    maxv = max(v for _, v in rows) or 1
    h = 26
    svg = [f"<svg viewBox='0 0 100 {len(rows) * h}' class='chart' "
           f"preserveAspectRatio='none' role='img'>"]
    for i, (name, val) in enumerate(rows):
        w = max(val / maxv * 62, 0.4)
        y = i * h
        color = colorfn(name, i) if colorfn else _PALETTE[i % len(_PALETTE)]
        svg.append(f"<rect x='0' y='{y + 4}' width='{w}' height='{h - 10}' rx='1.5' fill='{color}'/>")
        svg.append(f"<text x='1' y='{y + h/2 + 1}' class='blabel'>{html.escape(str(name))}</text>")
        svg.append(f"<text x='99' y='{y + h/2 + 1}' class='bval' text-anchor='end'>{val:,}{unit}</text>")
    svg.append("</svg>")
    return "".join(svg)


def _timeline_chart(timeline) -> str:
    if not timeline:
        return "<p class='empty'>no data</p>"
    maxv = max(timeline) or 1
    n = len(timeline)
    pts = [f"{(i / max(n - 1, 1)) * 100:.2f},{40 - (v / maxv) * 38:.2f}"
           for i, v in enumerate(timeline)]
    area = f"M0,40 L{' L'.join(pts)} L100,40 Z"
    return (f"<svg viewBox='0 0 100 40' class='timeline' preserveAspectRatio='none' role='img'>"
            f"<path d='{area}' fill='#3b82f6' fill-opacity='0.18'/>"
            f"<polyline points='{' '.join(pts)}' fill='none' stroke='#3b82f6' stroke-width='0.6'/></svg>"
            f"<p class='cap'>packets per second over {n}s</p>")


def render_html(s: dict, title: str = "Traffic Analysis") -> str:
    proto_color = lambda name, i: PROTO_COLOR.get(name, _PALETTE[i % len(_PALETTE)])
    cards = [("Packets", f"{s['packets']:,}"), ("Bytes", f"{s['bytes']:,}"),
             ("Duration", f"{s['duration']} s"), ("Rate", f"{s['pps']} pkt/s")]
    card_html = "".join(f"<div class='card'><div class='k'>{v}</div>"
                        f"<div class='l'>{html.escape(l)}</div></div>" for l, v in cards)

    def panel(t, body):
        return f"<section class='panel'><h2>{html.escape(t)}</h2>{body}</section>"

    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#f7f8fa;--fg:#1f2937;--muted:#6b7280;--panel:#ffffff;--line:#e5e7eb;}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --bg:#0f1420;--fg:#e5e7eb;--muted:#9ca3af;--panel:#171d2b;--line:#2a3344;}}}}
*{{box-sizing:border-box;}}
body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}}
.wrap{{max-width:900px;margin:0 auto;}}
h1{{font-size:22px;margin:0 0 4px;}}
.sub{{color:var(--muted);margin:0 0 20px;}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px;}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;}}
.card .k{{font-size:22px;font-weight:650;}}
.card .l{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px;}}
.panel h2{{font-size:14px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);}}
.chart{{width:100%;height:auto;}}
.blabel{{font-size:4.2px;fill:var(--fg);}}
.bval{{font-size:4.2px;fill:var(--muted);}}
.timeline{{width:100%;height:120px;}}
.cap,.empty{{color:var(--muted);font-size:12px;margin:6px 0 0;}}
footer{{color:var(--muted);font-size:12px;margin-top:8px;}}
</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<p class="sub">offline pcap analysis &middot; generated by traffic_analyzer.py</p>
<div class="cards">{card_html}</div>
{panel("Packets over time", _timeline_chart(s["timeline"]))}
{panel("Protocols (by packets)", _bar_chart(s["protocols"], colorfn=proto_color))}
{panel("Top talkers (bytes sent)", _bar_chart(s["top_talkers"], unit=" B"))}
{panel("Top destination ports", _bar_chart(s["top_ports"]))}
{panel("Top conversations (bytes)", _bar_chart(s["top_convos"], unit=" B"))}
<footer>Analyzes capture files only &mdash; does not sniff the network.</footer>
</div></body></html>"""


# ==========================================================================
# SECTION 4 - synthetic sample pcap generator
# ==========================================================================

_MAC_A = bytes.fromhex("001122334455")
_MAC_B = bytes.fromhex("66778899aabb")


def _eth(dst, src, etype):
    return dst + src + struct.pack(">H", etype)


def _ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def _tcp(sport, dport, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 64240, 0, 0) + payload


def _udp(sport, dport, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp_echo():
    return struct.pack(">BBHHH", 8, 0, 0, 1, 1)


def _frame(src, dst, proto, l4):
    return _eth(_MAC_B, _MAC_A, 0x0800) + _ipv4(src, dst, proto, l4)


def build_sample_packets() -> list[tuple[float, bytes]]:
    pkts, t = [], 1000.0
    client, http, dns, tls, client2 = (
        "192.168.1.10", "93.184.216.34", "8.8.8.8", "142.250.80.46", "192.168.1.11")
    for i in range(12):
        if i % 2 == 0:
            pkts.append((t, _frame(client, http, 6, _tcp(49000 + i, 80, 0x18,
                        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))))
        else:
            pkts.append((t, _frame(http, client, 6, _tcp(80, 49000 + i, 0x18,
                        b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 400))))
        t += 0.2
    for i in range(6):
        pkts.append((t, _frame(client, dns, 17, _udp(55000 + i, 53, b"\x00" * 30))))
        t += 0.1
    for i in range(5):
        pkts.append((t, _frame(client2, tls, 6, _tcp(52000 + i, 443, 0x18, b"\x16\x03" + b"z" * 200))))
        t += 0.15
    for _ in range(3):
        pkts.append((t, _frame(client, dns, 1, _icmp_echo())))
        t += 0.5
    return pkts


def build_sample_pcap_bytes() -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in build_sample_packets():
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return bytes(out)


def make_sample(out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "sample.pcap")
    with open(path, "wb") as fh:
        fh.write(build_sample_pcap_bytes())
    return path


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

    frame = _frame("10.0.0.1", "10.0.0.2", 6, _tcp(1234, 80, 0x18))
    pkt = {"ts": 1.0, "length": len(frame)}
    _decode_frame(frame, 1, pkt)
    check("decodes IPv4+TCP", pkt["l3"] == "IPv4" and pkt["l4"] == "TCP")
    check("dst port 80", pkt["dst_port"] == 80)

    with tempfile.TemporaryDirectory() as d:
        path = make_sample(d)
        packets, linktype = parse_pcap(path)
        check("linktype ethernet", linktype == 1)
        check("parsed all packets", len(packets) == len(build_sample_packets()))
        s = analyze(packets)
        protos = dict(s["protocols"])
        check("has TCP/UDP/ICMP",
              protos.get("TCP") and protos.get("UDP") and protos.get("ICMP"))
        check("client is top talker", "192.168.1.10" in dict(s["top_talkers"]))
        ports = " ".join(p for p, _ in s["top_ports"])
        check("http+dns ports surfaced", "80 (http)" in ports and "53 (dns)" in ports)
        h = render_html(s)
        check("html self-contained", "<svg" in h and "cdn" not in h.lower() and "src=" not in h)

    try:
        parse_pcap(os.devnull)
        check("rejects non-pcap", False)
    except PcapError:
        check("rejects non-pcap", True)

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


# ==========================================================================
# CLI
# ==========================================================================

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline pcap analyzer + visualizer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="analyze a .pcap capture")
    p_an.add_argument("pcap")
    p_an.add_argument("--html", metavar="FILE")
    p_an.add_argument("--json", action="store_true")
    p_an.add_argument("--top", type=int, default=10)

    p_mk = sub.add_parser("make-sample", help="write a synthetic sample.pcap")
    p_mk.add_argument("--out", default="samples")

    sub.add_parser("selftest", help="run built-in checks")
    args = ap.parse_args(argv)

    if args.cmd == "make-sample":
        print(f"wrote {make_sample(args.out)}")
        return 0
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "analyze":
        try:
            packets, linktype = parse_pcap(args.pcap)
        except (PcapError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        stats = analyze(packets, top=args.top)
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(render_text(stats))
            print(f"\n  (linktype {linktype}, {len(packets)} packets decoded)")
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_html(stats))
            print(f"\nwrote HTML report: {args.html}", file=sys.stderr)
        return 0
    return 2


def menu() -> int:
    """Interactive menu shown when the script is run with no arguments."""
    print("=" * 56)
    print("  traffic_analyzer - interactive menu")
    print("  Analyzes capture FILES only; never sniffs the network.")
    print("=" * 56)
    print("  1) Self-test")
    print("  2) Make a sample capture (into samples/)")
    print("  3) Analyze a .pcap (optional HTML report)")
    print("  4) Show full command-line help")
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
            path = input("pcap path [samples/sample.pcap]: ").strip() or "samples/sample.pcap"
            report = input("Write HTML report to (blank = none): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        argv = ["analyze", path] + (["--html", report] if report else [])
        return main(argv)
    if choice == "4":
        try:
            main(["-h"])
        except SystemExit:
            pass
        return 0
    return 0


if __name__ == "__main__":
    # No CLI arguments -> friendly menu; otherwise normal argparse handling.
    raise SystemExit(menu() if len(sys.argv) == 1 else main())
