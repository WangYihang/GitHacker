"""Minimal malicious HTTP server for security benchmark tests.

Three modes, selected by ``--mode``:

* ``static`` — serves files from ``--payload``. Used by tests where the
  malicious content lives in ``.git/`` files (e.g. a crafted ``config``
  with ``core.fsmonitor``, a poisoned ``index``, an HTML index with
  path-traversal anchors).
* ``redirect`` — responds to every request with a 302 redirect to
  ``--redirect-to``. Used by C2/C3 (redirect to ``file:///etc/passwd``
  or to an internal SSRF target).
* ``callback`` — touches ``--canary-file`` on the first HTTP request
  received and returns 200. Used as the SSRF target for C3 — if the
  pillager follows the redirect, the canary fires.

Apache-style directory listings are emitted for ``static`` mode so
recursive pillagers behave the same as they do against the existing
``apache-index-enabled`` perf scenario.

This script is intentionally dependency-free so it can be launched as a
subprocess on the host (or inside a tiny container) without dragging in
the benchmark package.
"""

from __future__ import annotations

import argparse
import html
import http.server
import os
import re
import socketserver
import sys
import urllib.parse
from pathlib import Path


class _StaticHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with an Apache-flavored autoindex.

    Pillagers detect a directory listing by scanning the body for
    ``<title>Index of`` (justinsteven 2022, GitHacker source) — the
    stdlib's default index uses a different title, so we override it.

    Class-level hooks ``access_log_path`` and ``watch_regex`` /
    ``watch_canary_path`` are wired up by ``main()`` from CLI flags.
    Any request whose path matches ``watch_regex`` causes
    ``watch_canary_path`` to be created — that is the trigger D1-style
    "observable side-effect" oracles read.
    """

    server_version = "EvilServer/0.1"
    access_log_path: Path | None = None
    watch_regex = None
    watch_canary_path: Path | None = None

    def _record(self) -> None:
        cls = self.__class__
        if cls.access_log_path:
            try:
                with open(cls.access_log_path, "a") as f:
                    f.write(self.requestline + "\n")
            except OSError as exc:
                sys.stderr.write(f"access-log write failed: {exc}\n")
        if cls.watch_regex and cls.watch_canary_path and cls.watch_regex.search(self.path):
            try:
                cls.watch_canary_path.parent.mkdir(parents=True, exist_ok=True)
                cls.watch_canary_path.write_text(
                    f"watch matched: {self.path}\n",
                )
            except OSError as exc:
                sys.stderr.write(f"watch canary write failed: {exc}\n")

    def do_GET(self):  # noqa: N802
        self._record()
        super().do_GET()

    def do_HEAD(self):  # noqa: N802
        self._record()
        super().do_HEAD()

    def list_directory(self, path):  # type: ignore[override]
        try:
            entries = sorted(os.listdir(path))
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None
        rel = urllib.parse.unquote(self.path)
        body = [
            "<!DOCTYPE html>",
            f"<html><head><title>Index of {html.escape(rel)}</title></head>",
            f"<body><h1>Index of {html.escape(rel)}</h1><hr><pre>",
            '<a href="../">../</a>',
        ]
        for name in entries:
            full = os.path.join(path, name)
            display = name + ("/" if os.path.isdir(full) else "")
            link = urllib.parse.quote(name) + ("/" if os.path.isdir(full) else "")
            body.append(f'<a href="{link}">{html.escape(display)}</a>')
        body.append("</pre><hr></body></html>")
        encoded = "\n".join(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        from io import BytesIO
        return BytesIO(encoded)


def _make_redirect_handler(target: str) -> type[http.server.BaseHTTPRequestHandler]:
    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        server_version = "EvilServer/0.1"

        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_HEAD = do_GET

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.address_string()} - - {fmt % args}\n")

    return _RedirectHandler


def _make_callback_handler(canary_path: Path) -> type[http.server.BaseHTTPRequestHandler]:
    class _CallbackHandler(http.server.BaseHTTPRequestHandler):
        server_version = "EvilServer/0.1"

        def do_GET(self):  # noqa: N802
            try:
                canary_path.parent.mkdir(parents=True, exist_ok=True)
                canary_path.write_text(f"hit from {self.client_address[0]} {self.path}\n")
            except OSError as exc:
                sys.stderr.write(f"callback failed to write canary: {exc}\n")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_HEAD = do_GET
        do_POST = do_GET

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.address_string()} - - {fmt % args}\n")

    return _CallbackHandler


class _ReusableServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    p = argparse.ArgumentParser(description="Evil HTTP server for security benchmarks")
    p.add_argument("--mode", choices=("static", "redirect", "callback"), default="static")
    p.add_argument("--payload", type=Path, help="Directory served in static mode")
    p.add_argument("--redirect-to", help="Target URL for redirect mode")
    p.add_argument("--canary-file", type=Path, help="File to touch in callback mode")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--access-log", type=Path,
                   help="Append every requestline to this file (static mode)")
    p.add_argument("--watch-regex",
                   help="Touch --watch-canary on any static request whose path matches this regex")
    p.add_argument("--watch-canary", type=Path,
                   help="File to touch when --watch-regex matches")
    args = p.parse_args()

    if args.mode == "static":
        if not args.payload or not args.payload.is_dir():
            p.error("--payload <dir> is required in static mode")
        os.chdir(args.payload)
        _StaticHandler.access_log_path = args.access_log
        if args.watch_regex:
            if not args.watch_canary:
                p.error("--watch-canary <path> is required when --watch-regex is set")
            _StaticHandler.watch_regex = re.compile(args.watch_regex)
            _StaticHandler.watch_canary_path = args.watch_canary
        handler: type[http.server.BaseHTTPRequestHandler] = _StaticHandler
    elif args.mode == "redirect":
        if not args.redirect_to:
            p.error("--redirect-to <url> is required in redirect mode")
        handler = _make_redirect_handler(args.redirect_to)
    else:  # callback
        if not args.canary_file:
            p.error("--canary-file <path> is required in callback mode")
        handler = _make_callback_handler(args.canary_file)

    with _ReusableServer((args.host, args.port), handler) as httpd:
        sys.stderr.write(f"evil-server listening on {args.host}:{args.port} ({args.mode})\n")
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
