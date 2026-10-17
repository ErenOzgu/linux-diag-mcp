"""Fixtures: a fake command runner, a made-up /proc and /sys, and ways to talk to the server."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from linux_diag_mcp import diag  # noqa: F401  (registers the tools)
from linux_diag_mcp.protocol import Server
from linux_diag_mcp.runner import NotInstalled, Result, RunFailed
from linux_diag_mcp.tools import REGISTRY, Context

ROOT = Path(__file__).resolve().parent.parent
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


class FakeRunner:
    """Records every command it is asked to run and answers from a table. Never starts a process."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.answers: list[tuple[str, Any]] = []  # (first word of the command, Result or Exception)

    def on(
        self, program: str, answer: Result | Exception | str, returncode: int = 0, stderr: str = ""
    ) -> FakeRunner:
        if isinstance(answer, str):
            answer = Result(returncode, answer, stderr)
        self.answers.append((program, answer))
        return self

    def run(self, argv: list[str], timeout: float = 10.0) -> Result:
        self.calls.append(list(argv))
        for program, answer in self.answers:
            if argv[0] == program:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise NotInstalled(argv[0])


def stat_line(
    pid: int,
    comm: str,
    state: str = "S",
    ppid: int = 1,
    utime: int = 0,
    stime: int = 0,
    threads: int = 1,
    start: int = 100,
    rss: int = 0,
) -> str:
    f = ["0"] * 50  # fields 3.. of proc(5), f[n - 3] is field n
    f[0], f[1] = state, str(ppid)
    f[11], f[12], f[17], f[19], f[21] = str(utime), str(stime), str(threads), str(start), str(rss)
    return f"{pid} ({comm}) " + " ".join(f)


def make_proc(tmp: Path) -> Path:
    """A small /proc: memory, load, mounts, sockets, and three processes."""
    p = tmp / "proc"
    (p / "net").mkdir(parents=True)
    (p / "self").mkdir()
    (p / "meminfo").write_text(
        "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\n"
        "Buffers:          100000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1500000 kB\nHugePages_Total:       0\n"
    )
    (p / "uptime").write_text("12345.67 5000.00\n")
    (p / "loadavg").write_text("0.50 1.00 2.00 1/100 999\n")
    (p / "self" / "mounts").write_text(
        "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n/dev/sdb1 /mnt/with\\040space ext4 ro 0 0\n"
        "/dev/loop0 /snap/core squashfs ro 0 0\n"
    )
    (p / "net" / "tcp").write_text(
        HEADER + "\n"
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0\n"
        "   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0 100 0 0 10 0\n"
        "   2: 0100007F:C350 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 3333 1 0 100 0 0 10 0\n"
    )
    (p / "net" / "tcp6").write_text(
        HEADER + "\n"
        "   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 4444 1 0 100 0 0 10 0\n"
        "   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5555 1 0 100 0 0 10 0\n"
    )
    (p / "net" / "udp").write_text(
        HEADER + "\n"
        "   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 6666 2 0 0\n"
    )
    (p / "net" / "udp6").write_text(HEADER + "\n")
    procs = [
        (1, "init", 100, 50, 4096, 1, ["socket:[1111]"]),
        (42, "web (worker) 2", 2000, 500, 40960, 4, ["socket:[2222]", "socket:[5555]", "pipe:[1]"]),
        (77, "idle", 0, 0, 100, 1, []),
    ]
    for pid, comm, utime, stime, rss_pages, threads, fds in procs:
        d = p / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "stat").write_text(
            stat_line(pid, comm, utime=utime, stime=stime, threads=threads, rss=rss_pages)
        )
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(
            b"/usr/bin/" + comm.split()[0].encode() + b"\0--password=hunter2\0--port\x0080\0"
        )
        for i, target in enumerate(fds):
            os.symlink(target, d / "fd" / str(i + 3))
    return p


def make_sys(tmp: Path) -> Path:
    s = tmp / "sys"
    for name, state, mtu, mac, rx in (
        ("eth0", "up", 1500, "02:00:00:00:00:01", 1000),
        ("lo", "unknown", 65536, "00:00:00:00:00:00", 5),
    ):
        d = s / "class" / "net" / name
        (d / "statistics").mkdir(parents=True)
        (d / "operstate").write_text(state + "\n")
        (d / "mtu").write_text(f"{mtu}\n")
        (d / "address").write_text(mac + "\n")
        for stat, value in (
            ("rx_bytes", rx),
            ("tx_bytes", 2),
            ("rx_errors", 0),
            ("tx_errors", 0),
            ("rx_dropped", 1),
            ("tx_dropped", 0),
        ):
            (d / "statistics" / stat).write_text(f"{value}\n")
    return s


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def logdir(tmp_path: Path) -> Path:
    d = tmp_path / "logs"
    d.mkdir()
    return Path(os.path.realpath(d))


@pytest.fixture
def ctx(tmp_path: Path, runner: FakeRunner, logdir: Path) -> Context:
    """A context over a made-up /proc and /sys, a fake runner and one log directory. Time does not pass."""
    clock = {"t": 1_000_000.0}

    def sleep(seconds: float) -> None:
        clock["t"] += seconds

    return Context(
        runner=runner,  # type: ignore[arg-type]
        allow_dirs=[logdir],
        proc=make_proc(tmp_path),
        sys=make_sys(tmp_path),
        sleep=sleep,
        now=lambda: clock["t"],
        monotonic=lambda: clock["t"],
    )


@pytest.fixture
def server(ctx: Context) -> Server:
    s = Server(ctx)
    s.initialized = True
    return s


def call(server: Server, name: str, arguments: Any = None, ident: Any = 1) -> dict[str, Any]:
    """tools/call through the server; returns the whole JSON-RPC response."""
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    resp = server.handle({"jsonrpc": "2.0", "id": ident, "method": "tools/call", "params": params})
    assert resp is not None
    return resp


def run_tool(server: Server, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """The structured result of a tool call that must succeed."""
    resp = call(server, name, arguments or {})
    assert "result" in resp, resp
    result = resp["result"]
    assert result["isError"] is False, result
    return result["structuredContent"]


def tool_error(server: Server, name: str, arguments: Any) -> str:
    """The message of a tool call that must come back as a tool error (not a protocol error)."""
    resp = call(server, name, arguments)
    assert "result" in resp, resp
    assert resp["result"]["isError"] is True, resp
    return resp["result"]["content"][0]["text"]


class Stdio:
    """The server as a real subprocess, spoken to in raw lines."""

    def __init__(self, *args: str, env: dict[str, str] | None = None, code: str | None = None) -> None:
        self.p = subprocess.Popen(
            [sys.executable, "-c", code, *args] if code else [sys.executable, "-m", "linux_diag_mcp", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env={**os.environ, **(env or {})},
        )

    def send(self, raw: bytes | dict | str) -> None:
        if isinstance(raw, dict):
            raw = json.dumps(raw)
        if isinstance(raw, str):
            raw = raw.encode()
        assert self.p.stdin
        self.p.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
        self.p.stdin.flush()

    def read(self) -> dict[str, Any]:
        assert self.p.stdout
        line = self.p.stdout.readline()
        assert line, "the server closed its output"
        return json.loads(line)

    def request(self, method: str, params: dict | None = None, ident: int = 1) -> dict[str, Any]:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": ident,
                "method": method,
                **({"params": params} if params is not None else {}),
            }
        )
        return self.read()

    def initialize(self) -> dict[str, Any]:
        r = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
            0,
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def finish(self) -> tuple[int, str]:
        assert self.p.stdin
        self.p.stdin.close()
        code = self.p.wait(timeout=10)
        assert self.p.stdout
        assert self.p.stdout.read() == b"", "unexpected output after the last response"
        assert self.p.stderr
        err = self.p.stderr.read().decode()
        self.p.stdout.close()
        self.p.stderr.close()
        return code, err


@pytest.fixture
def stdio():
    made: list[Stdio] = []

    def make(*args: str, env: dict[str, str] | None = None, code: str | None = None) -> Stdio:
        s = Stdio(*args, env=env, code=code)
        made.append(s)
        return s

    yield make
    for s in made:
        if s.p.poll() is None:
            s.p.kill()
            s.p.wait()
        for pipe in (s.p.stdin, s.p.stdout, s.p.stderr):
            if pipe and not pipe.closed:
                pipe.close()


__all__ = ["REGISTRY", "NotInstalled", "Result", "RunFailed"]
