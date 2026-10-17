"""linux-diag-mcp [--allow-dir DIR]... [--audit FILE] [--list-tools] [--version]"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, diag  # noqa: F401  (importing diag registers the tools)
from .protocol import Server
from .tools import REGISTRY, Context

DEFAULT_ALLOW = "/var/log"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux-diag-mcp",
        description="A read-only MCP server for Linux diagnostics. Speaks MCP over standard input and output.",
    )
    p.add_argument(
        "--allow-dir",
        action="append",
        metavar="DIR",
        help=f"a directory whose log files read_log and list_logs may show; repeatable (default {DEFAULT_ALLOW}). "
        "LINUX_DIAG_MCP_ALLOW_DIRS (colon-separated) adds more.",
    )
    p.add_argument("--audit", metavar="FILE", help="append one JSON line per tool call to this file")
    p.add_argument("--list-tools", action="store_true", help="print the tool definitions as JSON and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def allowed_dirs(given: list[str] | None, env: str | None) -> list[Path]:
    wanted = list(given or [])
    wanted += [d for d in (env or "").split(":") if d]
    if not wanted:
        wanted = [DEFAULT_ALLOW]
    roots: list[Path] = []
    for d in wanted:
        if not d.startswith("/"):
            raise SystemExit(f"linux-diag-mcp: --allow-dir must be an absolute path, not {d!r}")
        real = Path(os.path.realpath(d))
        if real == Path("/"):
            raise SystemExit("linux-diag-mcp: refusing to allow the whole file system (/)")
        if not real.is_dir():
            print(f"linux-diag-mcp: warning: {d} is not a directory, ignoring it", file=sys.stderr)
            continue
        if real not in roots:
            roots.append(real)
    return roots


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_tools:
        print(json.dumps([t.definition() for t in REGISTRY.values()], indent=2))
        return 0
    ctx = Context(allow_dirs=allowed_dirs(args.allow_dir, os.environ.get("LINUX_DIAG_MCP_ALLOW_DIRS")))
    audit = None
    if args.audit:
        log = open(args.audit, "a", encoding="utf-8", buffering=1)  # noqa: SIM115

        def audit(entry: dict) -> None:  # type: ignore[misc]
            from datetime import UTC, datetime

            entry = {"time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), **entry}
            log.write(json.dumps(entry, ensure_ascii=True) + "\n")

    # The protocol owns the real stdout. Anything else that prints goes to stderr instead of the stream.
    out = sys.stdout.buffer
    sys.stdout = sys.stderr
    try:
        Server(ctx, audit=audit).serve(sys.stdin.buffer, out)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
