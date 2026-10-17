"""The server as a real process, talked to over real pipes."""

import json
import os

import pytest

from linux_diag_mcp import __version__, cli
from linux_diag_mcp.tools import REGISTRY

from .conftest import ROOT


def test_a_whole_session(stdio, logdir):
    (logdir / "app.log").write_text("one\ntwo password=abc123\nthree\n")
    s = stdio("--allow-dir", str(logdir))
    init = s.initialize()["result"]
    assert init["serverInfo"]["name"] == "linux-diag-mcp"
    names = [t["name"] for t in s.request("tools/list", {}, 2)["result"]["tools"]]
    assert names == list(REGISTRY)
    r = s.request(
        "tools/call", {"name": "read_log", "arguments": {"path": str(logdir / "app.log"), "lines": 2}}, 3
    )["result"]
    assert r["structuredContent"]["lines"] == ["two password=<secret>", "three"]
    assert s.request("ping", None, 4)["result"] == {}
    code, err = s.finish()
    assert code == 0
    assert err == ""


def test_closing_stdin_ends_the_process_cleanly_without_a_request(stdio):
    s = stdio()
    assert s.finish() == (0, "")


def test_stdout_is_protocol_only_even_when_a_tool_prints_and_crashes(stdio):
    code = """
import sys
from linux_diag_mcp import cli, diag
from linux_diag_mcp.tools import tool

@tool("noisy", "Noisy", "prints to standard output and then crashes, for the test " * 2)
def noisy(ctx, args):
    print("STRAY OUTPUT")
    raise RuntimeError("secret internal detail")

sys.exit(cli.main())
"""
    s = stdio(code=code)
    s.initialize()
    r = s.request("tools/call", {"name": "noisy", "arguments": {}}, 5)["result"]
    assert r["isError"] is True
    assert "secret internal detail" not in json.dumps(r)
    assert s.request("ping", None, 6)["result"] == {}  # the stream was not corrupted
    status, err = s.finish()
    assert status == 0
    assert "STRAY OUTPUT" in err and "secret internal detail" in err


def test_garbage_between_good_requests_does_not_stop_the_session(stdio):
    s = stdio()
    s.initialize()
    s.send(b"this is not json")
    assert s.read()["error"]["code"] == -32700
    s.send(b"\xff\xfe\xfd")
    assert s.read()["error"]["code"] == -32700
    s.send(b"[1,2,3]")
    assert s.read()["error"]["code"] == -32600
    s.send(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
    assert s.read()["result"] == {}
    assert s.finish()[0] == 0


def test_a_two_megabyte_line_is_refused_and_the_session_goes_on(stdio):
    s = stdio()
    s.initialize()
    s.send(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"' + b"a" * 2_000_000 + b'"}}')
    r = s.read()
    assert r["error"]["code"] == -32600 and r["id"] is None
    assert s.request("ping", None, 2)["result"] == {}
    assert s.finish()[0] == 0


def test_two_hundred_pipelined_requests_are_answered_in_order(stdio):
    s = stdio()
    s.initialize()
    for i in range(200):
        s.send({"jsonrpc": "2.0", "id": i, "method": "ping"})
    assert [s.read()["id"] for _ in range(200)] == list(range(200))
    assert s.finish()[0] == 0


def test_tool_output_with_odd_characters_stays_on_one_line(stdio, logdir):
    (logdir / "odd.log").write_bytes("a b ‮ reversed \x1b[31mred\x1b[0m \x00 nul \U0001f642\n".encode())
    s = stdio("--allow-dir", str(logdir))
    s.initialize()
    r = s.request("tools/call", {"name": "read_log", "arguments": {"path": str(logdir / "odd.log")}}, 9)
    assert r["result"]["isError"] is True  # the NUL makes it a binary file
    (logdir / "odd.log").write_bytes("a b ‮ reversed \x1b[31mred\x1b[0m \U0001f642\n".encode())
    r = s.request("tools/call", {"name": "read_log", "arguments": {"path": str(logdir / "odd.log")}}, 10)
    assert r["result"]["structuredContent"]["lines"] == ["a", "b  reversed red \U0001f642"]
    assert s.finish()[0] == 0


class TestCommandLine:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as e:
            cli.main(["--version"])
        assert e.value.code == 0
        assert capsys.readouterr().out.strip() == f"linux-diag-mcp {__version__}"

    def test_list_tools_prints_the_definitions(self, capsys):
        assert cli.main(["--list-tools"]) == 0
        listed = json.loads(capsys.readouterr().out)
        assert [t["name"] for t in listed] == list(REGISTRY)

    def test_unknown_option_exits_two(self):
        with pytest.raises(SystemExit) as e:
            cli.parse_args(["--wat"])
        assert e.value.code == 2

    def test_the_default_is_var_log(self, monkeypatch):
        monkeypatch.delenv("LINUX_DIAG_MCP_ALLOW_DIRS", raising=False)
        assert [str(r) for r in cli.allowed_dirs(None, None)] == [os.path.realpath("/var/log")]

    def test_dirs_are_resolved_deduplicated_and_combined_with_the_environment(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        os.symlink(a, tmp_path / "alias")
        roots = cli.allowed_dirs([str(a), str(tmp_path / "alias")], str(b))
        assert [str(r) for r in roots] == [os.path.realpath(a), os.path.realpath(b)]

    def test_a_relative_directory_is_refused(self):
        with pytest.raises(SystemExit, match="absolute"):
            cli.allowed_dirs(["logs"], None)

    @pytest.mark.parametrize("bad", ["/", "//", "/../", "/tmp/.."])
    def test_the_whole_file_system_is_refused_however_it_is_spelled(self, bad):
        with pytest.raises(SystemExit, match="whole file system"):
            cli.allowed_dirs([bad], None)

    def test_a_missing_directory_is_ignored_with_a_warning(self, tmp_path, capsys):
        assert cli.allowed_dirs([str(tmp_path / "nope")], None) == []
        assert "not a directory" in capsys.readouterr().err

    def test_a_file_is_not_a_directory(self, tmp_path):
        (tmp_path / "f").write_text("x")
        assert cli.allowed_dirs([str(tmp_path / "f")], None) == []

    def test_without_an_allowed_directory_log_tools_refuse(self, stdio, tmp_path):
        s = stdio("--allow-dir", str(tmp_path / "missing"))
        s.initialize()
        r = s.request("tools/call", {"name": "read_log", "arguments": {"path": "/var/log/syslog"}}, 1)[
            "result"
        ]
        assert r["isError"] and "--allow-dir" in r["content"][0]["text"]
        s.finish()

    def test_the_environment_variable_adds_directories(self, stdio, logdir):
        (logdir / "e.log").write_text("from env\n")
        s = stdio(env={"LINUX_DIAG_MCP_ALLOW_DIRS": str(logdir)})
        s.initialize()
        r = s.request("tools/call", {"name": "read_log", "arguments": {"path": str(logdir / "e.log")}}, 1)[
            "result"
        ]
        assert r["structuredContent"]["lines"] == ["from env"]
        s.finish()

    def test_the_audit_file_gets_one_line_per_call(self, stdio, tmp_path, logdir):
        audit = tmp_path / "audit.jsonl"
        s = stdio("--allow-dir", str(logdir), "--audit", str(audit))
        s.initialize()
        s.request("tools/call", {"name": "system_overview", "arguments": {}}, 1)
        s.request("tools/call", {"name": "read_log", "arguments": {"path": "/etc/passwd"}}, 2)
        s.request("tools/list", {}, 3)
        s.finish()
        rows = [json.loads(x) for x in audit.read_text().splitlines()]
        assert [(r["tool"], r["ok"]) for r in rows] == [("system_overview", True), ("read_log", False)]
        assert rows[1]["arguments"] == {"path": "/etc/passwd"}
        assert rows[0]["time"].endswith("Z")


def test_the_package_is_importable_from_a_different_directory(tmp_path):
    import subprocess
    import sys

    p = subprocess.run(
        [sys.executable, "-m", "linux_diag_mcp", "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        check=False,
    )
    assert p.returncode == 0 and __version__ in p.stdout
