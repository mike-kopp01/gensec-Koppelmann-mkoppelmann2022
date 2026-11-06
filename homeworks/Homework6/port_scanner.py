#!/usr/bin/env python3
"""
port_scanner.py  --  an nmap-style asynchronous TCP/UDP port scanner.

Coursework reimplementation of core nmap functionality. TCP *connect* scanning
via asyncio, so it needs no root/admin and runs on Windows.

    !!  AUTHORIZED USE ONLY  !!
    Only scan hosts you own or have explicit written permission to test.

Subcommands / usage
-------------------
    python port_scanner.py 127.0.0.1 -p 1-1024
    python port_scanner.py 10.0.0.0/24 --top-ports 50 --banner --open
    python port_scanner.py scanme.example.test -p 22,80,443 --json
    python port_scanner.py --selftest

Stdlib only (Python 3.10+).
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sys
import time

SERVICES = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 515: "printer",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9000: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}
HTTP_PORTS = {80, 591, 3000, 8000, 8008, 8080, 8888, 9000}
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9,
    5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]


# -------------------------------------------------------------------------
# spec parsing
# -------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            out.update(range(lo, hi + 1))
        else:
            out.add(int(part))
    bad = [p for p in out if p < 1 or p > 65535]
    if bad:
        raise ValueError(f"port out of range: {bad[0]}")
    return sorted(out)


def parse_targets(spec: str) -> list[str]:
    out, seen = [], set()

    def add(h):
        if h and h not in seen:
            seen.add(h)
            out.append(h)

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            for ip in (net if net.num_addresses <= 2 else net.hosts()):
                add(str(ip))
        elif "-" in part and part.count(".") == 3:
            head, rng = part.rsplit(".", 1)
            lo, hi = (int(x) for x in rng.split("-", 1))
            for n in range(lo, hi + 1):
                add(f"{head}.{n}")
        else:
            add(part)
    return out


# -------------------------------------------------------------------------
# scanning
# -------------------------------------------------------------------------

async def _read_banner(reader, writer, host, port, timeout):
    try:
        if port in HTTP_PORTS:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout)
        if not data:
            return None
        lines = data.decode("latin-1", "ignore").strip().splitlines()
        return (lines[0][:120] if lines else None) or None
    except Exception:
        return None


async def scan_port(host, port, timeout=1.0, sem=None, banner=False) -> dict:
    sem = sem or asyncio.Semaphore(1)
    service = SERVICES.get(port, "")
    async with sem:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout)
            ban = await _read_banner(reader, writer, host, port, timeout) if banner else None
            state = "open"
        except asyncio.TimeoutError:
            return {"port": port, "state": "filtered", "service": service, "banner": None}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed", "service": service, "banner": None}
        except Exception:
            return {"port": port, "state": "filtered", "service": service, "banner": None}
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
    return {"port": port, "state": state, "service": service, "banner": ban}


async def scan_udp_port(host, port, timeout=2.0, sem=None) -> dict:
    sem = sem or asyncio.Semaphore(1)
    service = SERVICES.get(port, "")
    async with sem:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (host, port))
            await loop.sock_sendall(sock, b"\x00")
            try:
                await asyncio.wait_for(loop.sock_recv(sock, 256), timeout)
                state = "open"
            except asyncio.TimeoutError:
                state = "open|filtered"
            except ConnectionRefusedError:
                state = "closed"
        except Exception:
            state = "open|filtered"
        finally:
            sock.close()
    return {"port": port, "state": state, "service": service, "banner": None}


async def scan_host(host, ports, timeout=1.0, concurrency=200, banner=False,
                    udp=False) -> dict:
    sem = asyncio.Semaphore(concurrency)
    tasks = ([scan_udp_port(host, p, timeout, sem) for p in ports] if udp
             else [scan_port(host, p, timeout, sem, banner) for p in ports])
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: r["port"])
    return {"host": host, "ports": results}


async def scan_targets(targets, ports, **kw) -> list[dict]:
    return [await scan_host(t, ports, **kw) for t in targets]


# -------------------------------------------------------------------------
# output / self-test / CLI
# -------------------------------------------------------------------------

def _print_host(h, open_only):
    shown = [p for p in h["ports"] if not open_only or p["state"].startswith("open")]
    up = sum(1 for p in h["ports"] if p["state"].startswith("open"))
    print(f"\nScan report for {h['host']}  ({up} open)")
    if not shown:
        print("  (no ports to show)")
        return
    print(f"  {'PORT':<10}{'STATE':<14}{'SERVICE':<16}BANNER")
    for p in shown:
        print(f"  {str(p['port']) + '/tcp':<10}{p['state']:<14}"
              f"{p['service'] or '-':<16}{p['banner'] or ''}")


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

    check("ports 22,80,1-3", parse_ports("22,80,1-3") == [1, 2, 3, 22, 80])
    check("cidr /30", parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"])
    check("octet range", parse_targets("192.168.1.1-3")
          == ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    open_port = listener.getsockname()[1]
    s2 = socket.socket()
    s2.bind(("127.0.0.1", 0))
    closed_port = s2.getsockname()[1]
    s2.close()
    try:
        host = asyncio.run(scan_host("127.0.0.1", [open_port, closed_port], timeout=1.0))
        states = {p["port"]: p["state"] for p in host["ports"]}
        check("listening port -> open", states[open_port] == "open")
        check("unused port -> closed/filtered",
              states[closed_port] in ("closed", "filtered"))
    finally:
        listener.close()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="nmap-style async TCP/UDP port scanner")
    ap.add_argument("targets", nargs="?", help="host / IP / CIDR / a.b.c.x-y / comma list")
    ap.add_argument("-p", "--ports")
    ap.add_argument("--top-ports", type=int, metavar="N")
    ap.add_argument("-t", "--timeout", type=float, default=1.0)
    ap.add_argument("-c", "--concurrency", type=int, default=200)
    ap.add_argument("--banner", action="store_true")
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--open", dest="open_only", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.targets:
        ap.error("targets required (or use --selftest)")

    if args.top_ports:
        ports = sorted(TOP_PORTS[:args.top_ports])
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = sorted(TOP_PORTS[:100])

    try:
        targets = parse_targets(args.targets)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("port_scanner - AUTHORIZED USE ONLY. Scan only hosts you may test.",
          file=sys.stderr)
    print(f"Scanning {len(targets)} host(s), {len(ports)} port(s) "
          f"[{'udp' if args.udp else 'tcp'}]...", file=sys.stderr)

    start = time.time()
    results = asyncio.run(scan_targets(
        targets, ports, timeout=args.timeout, concurrency=args.concurrency,
        banner=args.banner, udp=args.udp))
    elapsed = time.time() - start

    if args.json:
        print(json.dumps({"elapsed": round(elapsed, 2), "hosts": results}, indent=2))
    else:
        for h in results:
            _print_host(h, args.open_only)
        print(f"\nDone in {elapsed:.2f}s", file=sys.stderr)
    return 0


def menu() -> int:
    """Interactive menu shown when the script is run with no arguments."""
    print("=" * 56)
    print("  port_scanner - interactive menu")
    print("  AUTHORIZED USE ONLY: scan only hosts you may test.")
    print("=" * 56)
    print("  1) Self-test (no network)")
    print("  2) Scan a host")
    print("  3) Show full command-line help")
    print("  q) Quit")
    try:
        choice = input("Select: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 0
    if choice == "1":
        return selftest()
    if choice == "2":
        try:
            target = input("Target host / IP / CIDR [127.0.0.1]: ").strip() or "127.0.0.1"
            ports = input("Ports (e.g. 1-1024; blank = top 100): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        argv = [target] + (["-p", ports] if ports else ["--top-ports", "100"]) + ["--open"]
        return main(argv)
    if choice == "3":
        try:
            main(["-h"])
        except SystemExit:
            pass
        return 0
    return 0


if __name__ == "__main__":
    # No CLI arguments -> friendly menu; otherwise normal argparse handling.
    raise SystemExit(menu() if len(sys.argv) == 1 else main())
