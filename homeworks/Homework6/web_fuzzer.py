#!/usr/bin/env python3
"""
web_fuzzer.py  --  a wfuzz-style HTTP fuzzer.

Coursework reimplementation of core wfuzz functionality (stdlib only). Put the
keyword FUZZ in a URL, header, or body; each wordlist entry is substituted,
sent, and the responses are filtered so the interesting ones stand out.

    !!  AUTHORIZED USE ONLY  !!
    Only fuzz applications you own or have explicit written permission to test.

Usage
-----
    python web_fuzzer.py http://target.lab/FUZZ -w words.txt --hc 404
    python web_fuzzer.py http://target.lab/login -X POST \\
        --data "user=admin&pass=FUZZ" -w passwords.txt --sc 200
    python web_fuzzer.py --selftest

Filters (comma lists): --sc/--hc codes, --sl/--hl lines, --sw/--hw words,
--sh/--hh chars  (s = show only, h = hide).

Stdlib only (Python 3.10+).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

DEFAULT_WORDS = [
    "admin", "administrator", "login", "logout", "index", "index.php",
    "index.html", "home", "dashboard", "api", "api/v1", "config", "config.php",
    "configuration", "backup", "backups", "db", "database", "test", "tests",
    "dev", "staging", "old", "new", "tmp", "temp", "uploads", "upload",
    "images", "img", "css", "js", "assets", "static", "robots.txt",
    ".git", ".git/config", ".env", "server-status", "phpinfo.php", "info.php",
    "wp-admin", "wp-login.php", "secret", "private", "hidden", "debug",
]
KEYWORD = "FUZZ"


def apply_fuzz(template, word):
    """Replace the FUZZ placeholder in a string template with a payload word.

    Returns None when the template is absent so callers can treat missing values
    consistently before building a request.
    """
    return None if template is None else template.replace(KEYWORD, word)


def _build_opener(follow: bool):
    """Create a urllib opener with optional redirect following disabled."""
    handlers = []
    if not follow:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            """Prevent HTTP redirects so the raw response can be inspected."""

            def redirect_request(self, *a, **k):
                """Return None to disable redirect handling for this request."""
                return None

        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def fuzz_one(opener, url_t, word, method, headers_t, data_t, timeout) -> dict:
    """Issue one HTTP request for a single payload and return response metrics."""
    url = apply_fuzz(url_t, word)
    headers = {k: apply_fuzz(v, word) for k, v in headers_t.items()}
    data = apply_fuzz(data_t, word)
    req = urllib.request.Request(url, data=data.encode() if data is not None else None,
                                 method=method, headers=headers)
    start = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
        code, body, location = resp.status, resp.read(), resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read()
        location = e.headers.get("Location") if e.headers else None
    except Exception as e:
        return {"word": word, "error": str(e), "code": None, "chars": 0,
                "words": 0, "lines": 0, "ms": 0, "location": None}
    text = body.decode("latin-1", "ignore")
    return {"word": word, "error": None, "code": code, "chars": len(body),
            "words": len(text.split()), "lines": text.count("\n"),
            "ms": int((time.time() - start) * 1000), "location": location}


def _intset(spec):
    """Parse a comma-separated filter spec into a set of integers."""
    return {int(p.strip()) for p in spec.split(",") if p.strip()} if spec else set()


class Filters:
    """Represent the include/exclude rules used to decide which responses print."""

    def __init__(self, args):
        """Initialize the filter sets from parsed command-line arguments."""
        self.sc, self.hc = _intset(args.sc), _intset(args.hc)
        self.sl, self.hl = _intset(args.sl), _intset(args.hl)
        self.sw, self.hw = _intset(args.sw), _intset(args.hw)
        self.sh, self.hh = _intset(args.sh), _intset(args.hh)
        self.fingerprint = None
        self.autofilter = not args.no_autofilter

    @property
    def has_show(self):
        """Return True when any positive show filter is active."""
        return any([self.sc, self.sl, self.sw, self.sh])

    def visible(self, r):
        """Return True if a response matches the currently active filters."""
        if r["error"] is not None:
            return False
        if self.sc and r["code"] not in self.sc:
            return False
        if self.sl and r["lines"] not in self.sl:
            return False
        if self.sw and r["words"] not in self.sw:
            return False
        if self.sh and r["chars"] not in self.sh:
            return False
        if r["code"] in self.hc or r["lines"] in self.hl:
            return False
        if r["words"] in self.hw or r["chars"] in self.hh:
            return False
        if (self.autofilter and self.fingerprint and not self.has_show
                and r["code"] == self.fingerprint[0]
                and r["chars"] == self.fingerprint[1]):
            return False
        return True


def calibrate(opener, url_t, method, headers_t, data_t, timeout):
    """Probe the target once to detect the normal response fingerprint."""
    if (KEYWORD not in (url_t or "") and KEYWORD not in (data_t or "")
            and not any(KEYWORD in v for v in headers_t.values())):
        return None
    probe = "zz" + uuid.uuid4().hex + "zz"
    r = fuzz_one(opener, url_t, probe, method, headers_t, data_t, timeout)
    return (r["code"], r["chars"]) if r["error"] is None else None


def run_fuzz(url_t, words, method="GET", headers_t=None, data_t=None,
             timeout=10.0, concurrency=30, delay=0.0, follow=False) -> list[dict]:
    """Send the supplied wordlist to the target URL concurrently and return results."""
    headers_t = headers_t or {}
    opener = _build_opener(follow)

    def task(word):
        """Handle one payload in a worker thread and return its response summary."""
        if delay:
            time.sleep(delay)
        return fuzz_one(opener, url_t, word, method, headers_t, data_t, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        return list(ex.map(task, words))


def _print_table(results, filters):
    """Print the summary table for a fuzzing run, with filtering applied."""
    print(f"\n{'RESPONSE':<10}{'LINES':<8}{'WORDS':<8}{'CHARS':<9}{'MS':<7}PAYLOAD")
    print("-" * 70)
    shown = 0
    for r in results:
        if not filters.visible(r):
            continue
        shown += 1
        loc = f"  -> {r['location']}" if r.get("location") else ""
        print(f"{str(r['code']):<10}{r['lines']:<8}{r['words']:<8}"
              f"{r['chars']:<9}{r['ms']:<7}{r['word']}{loc}")
    errs = [r for r in results if r["error"]]
    if errs:
        print(f"\n{len(errs)} request(s) errored, e.g.: {errs[0]['error']}")
    print(f"\n{shown} shown / {len(results)} sent", file=sys.stderr)


class _Args:
    """Simple namespace used by self-tests to emulate parsed arguments."""

    sc = hc = sl = hl = sw = hw = sh = hh = None
    no_autofilter = False


def selftest() -> int:
    """Run a local end-to-end check of the fuzzer against a temporary server."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  ok   - {name}")
        else:
            failed += 1
            print(f"  FAIL - {name}")

    real = {"/admin": b"SECRET ADMIN PANEL", "/login": b"<form>login</form>"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = real.get(self.path)
            self.send_response(200 if body else 404)
            if body is None:
                body = b"404 - not found (fixed length body)"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(n).decode()
            ok = "pass=hunter2" in data
            body = b"welcome" if ok else b"denied!!"
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    check("url sub", apply_fuzz("http://h/FUZZ", "x") == "http://h/x")

    srv = HTTPServer(("127.0.0.1", 0), H)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = run_fuzz(base + "/FUZZ", ["admin", "login", "nope"], concurrency=4)
        by = {r["word"]: r for r in res}
        check("admin -> 200", by["admin"]["code"] == 200)
        check("nope -> 404", by["nope"]["code"] == 404)

        f = Filters(_Args())
        f.fingerprint = calibrate(_build_opener(False), base + "/FUZZ", "GET", {}, None, 5.0)
        check("calibrated to 404", f.fingerprint and f.fingerprint[0] == 404)
        check("autofilter hides 404s",
              {r["word"] for r in res if f.visible(r)} == {"admin", "login"})

        post = run_fuzz(base + "/login", ["wrong", "hunter2"], method="POST",
                        data_t="user=admin&pass=FUZZ", concurrency=2)
        pby = {r["word"]: r for r in post}
        check("correct pass -> 200", pby["hunter2"]["code"] == 200)
        check("wrong pass -> 401", pby["wrong"]["code"] == 401)
    finally:
        srv.shutdown()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def _resolve_path(path: str):
    """Find a file at the given path, or next to this script; None if missing."""
    if os.path.isfile(path):
        return path
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    return here if os.path.isfile(here) else None


def main(argv=None) -> int:
    """Parse CLI arguments and execute the requested fuzzing workflow."""
    ap = argparse.ArgumentParser(description="wfuzz-style HTTP fuzzer")
    ap.add_argument("url", nargs="?", help="target URL; put FUZZ where the payload goes")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-X", "--method", default="GET")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-d", "--data")
    ap.add_argument("-t", "--concurrency", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("-L", "--follow", action="store_true")
    ap.add_argument("--no-autofilter", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    for f in ("sc", "hc", "sl", "hl", "sw", "hw", "sh", "hh"):
        ap.add_argument(f"--{f}", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.url:
        ap.error("url required (or use --selftest)")

    headers_t = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers_t[k.strip()] = v.strip()

    if (KEYWORD not in args.url and KEYWORD not in (args.data or "")
            and not any(KEYWORD in v for v in headers_t.values())):
        print(f"error: no {KEYWORD} keyword in url/data/headers", file=sys.stderr)
        return 2

    if args.wordlist:
        wl_path = _resolve_path(args.wordlist)
        if wl_path is None:
            print(f"error: wordlist not found: {args.wordlist}", file=sys.stderr)
            return 2
        with open(wl_path, encoding="latin-1") as fh:
            words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    else:
        words = DEFAULT_WORDS

    print("web_fuzzer - AUTHORIZED USE ONLY. Fuzz only apps you may test.",
          file=sys.stderr)
    print(f"Target: {args.url}  |  {len(words)} payloads  |  {args.method}",
          file=sys.stderr)

    filters = Filters(args)
    if filters.autofilter and not filters.has_show:
        filters.fingerprint = calibrate(_build_opener(args.follow), args.url,
                                        args.method, headers_t, args.data, args.timeout)
        if filters.fingerprint:
            print(f"Auto-calibrated: hiding code={filters.fingerprint[0]} "
                  f"chars={filters.fingerprint[1]}", file=sys.stderr)

    start = time.time()
    results = run_fuzz(args.url, words, method=args.method, headers_t=headers_t,
                       data_t=args.data, timeout=args.timeout,
                       concurrency=args.concurrency, delay=args.delay,
                       follow=args.follow)
    elapsed = time.time() - start

    if args.json:
        vis = [r for r in results if filters.visible(r)]
        print(json.dumps({"elapsed": round(elapsed, 2), "sent": len(results),
                          "shown": len(vis), "results": vis}, indent=2))
    else:
        _print_table(results, filters)
        print(f"Done in {elapsed:.2f}s", file=sys.stderr)
    return 0


def menu() -> int:
    """Display a simple interactive menu when the script is launched without args."""
    print("=" * 56)
    print("  web_fuzzer - interactive menu")
    print("  AUTHORIZED USE ONLY: fuzz only apps you may test.")
    print("=" * 56)
    print("  1) Self-test (uses a temporary local server)")
    print("  2) Fuzz a URL")
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
            url = input("Target URL (must contain FUZZ): ").strip()
            wl = input("Wordlist file (blank = built-in list): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if not url:
            print("no URL given", file=sys.stderr)
            return 2
        argv = [url] + (["-w", wl] if wl else [])
        return main(argv)
    if choice == "3":
        try:
            main(["-h"])
        except SystemExit:
            pass
        return 0
    return 0


if __name__ == "__main__":
    """Run the interactive menu when no arguments are supplied; otherwise start CLI mode."""
    # No CLI arguments -> friendly menu; otherwise normal argparse handling.
    raise SystemExit(menu() if len(sys.argv) == 1 else main())
