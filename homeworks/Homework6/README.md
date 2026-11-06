# Homework 6 — Security Tools

**Course:** GenSec · **Author:** Michael Koppelmann

A set of four small security tools written in **pure Python 3** (standard
library only — no `pip install` needed). Each tool is a single self-contained
file, runs on Windows, and ships with a built-in self-test and an interactive
menu.

## Scope & ethics

The assignment brief mixed legitimate security tools with two pieces of
malware — a data-exfiltration Office macro and a `cmd.exe` backdoor DLL. Those
were **not** built. Instead, their **detection** counterparts were, since the
goal of a security course is to understand a threat well enough to detect it,
not to produce a working weapon.

Every offensive tool prints an **"AUTHORIZED USE ONLY"** notice and is intended
only for hosts/apps you own or have written permission to test (lab machines).

## The tools

| File | Purpose | Modeled on |
|------|---------|------------|
| `detection_tools.py` | Static VBA **macro analyzer** + **RunDLL backdoor detector** | olevba / PE triage |
| `port_scanner.py` | Asynchronous TCP/UDP **port scanner** | nmap |
| `web_fuzzer.py` | HTTP **fuzzer** (directory discovery, form testing) | wfuzz |
| `traffic_analyzer.py` | Offline **pcap analyzer + HTML visualizer** | Wireshark (analysis) |

- **detection_tools.py** — reads files only, never executes anything. The macro
  analyzer implements MS-OVBA decompression from scratch to recover hidden VBA
  source and flag auto-run / shell / download indicators. The DLL detector is a
  from-scratch PE parser that flags the `rundll32 → cmd.exe` pattern. Includes
  an inert test-sample generator.
- **port_scanner.py** — TCP connect scan (no admin needed) plus a UDP probe
  mode. Handles single hosts, CIDR ranges, and octet ranges; labels services;
  does banner grabbing and JSON output.
- **web_fuzzer.py** — substitutes the keyword `FUZZ` in a URL/header/body with
  each wordlist entry, with wfuzz-style response filters and auto-calibration
  that hides "not found" responses.
- **traffic_analyzer.py** — decodes Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP
  by hand and renders a self-contained HTML report. Reads capture files only;
  never sniffs the network.

## How to run

Run any file **with no arguments** for an interactive menu (self-test, run the
tool, help):

