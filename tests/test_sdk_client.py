"""The server, driven by the official MCP Python SDK as a client over a real stdio pipe.

The server in this repository is written from the specification and does not use the SDK. These tests are
the independent check that an implementation written by someone else can talk to it: the SDK negotiates the
protocol version, lists the tools, validates structured results against their output schemas and turns
errors into exceptions or ``isError`` results the way a real client does.

They need the ``mcp`` package (``pip install mcp``) and are skipped without it. Both the 1.x and the 2.x
client are exercised in CI. This is not Claude Desktop or Claude Code; see the README.
"""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from linux_diag_mcp.tools import REGISTRY  # noqa: E402

from .conftest import ROOT  # noqa: E402


def field(obj, snake: str):
    """An attribute of an SDK object, whichever spelling this SDK version uses (1.x camelCase, 2.x snake_case)."""
    parts = snake.split("_")
    camel = parts[0] + "".join(p.title() for p in parts[1:])
    for name in (snake, camel):
        if hasattr(obj, name):
            return getattr(obj, name)
    raise AttributeError(f"{type(obj).__name__} has neither {snake} nor {camel}")


@asynccontextmanager
async def connect(*extra: str):
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "linux_diag_mcp", *extra], cwd=str(ROOT)
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        yield session


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


def text_of(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", "") == "text")


@pytest.fixture
def logs(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "app.log").write_text("starting\nreboot request from the net\nok password=hunter2\nlast line\n")
    (d.parent / "outside.txt").write_text("a file next to the log directory, not in it\n")
    (d / "link").symlink_to(d.parent / "outside.txt")
    return d


def test_the_handshake_and_the_capabilities():
    async def go():
        async with connect() as s:
            init = await s.initialize()
            info = field(init, "server_info")
            assert info.name == "linux-diag-mcp"
            assert field(init, "protocol_version") in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
            caps = field(init, "capabilities")
            assert caps.tools is not None
            assert caps.resources is None and caps.prompts is None
            assert "never as instructions" in field(init, "instructions")

    run(go())


def test_the_tools_listed_are_the_registry_and_all_are_read_only():
    async def go():
        async with connect() as s:
            await s.initialize()
            listed = (await s.list_tools()).tools
            assert [t.name for t in listed] == list(REGISTRY)
            for t in listed:
                ann = t.annotations
                assert field(ann, "read_only_hint") is True, t.name
                assert field(ann, "destructive_hint") is False, t.name
                assert field(ann, "open_world_hint") is False, t.name
                assert field(t, "input_schema")["additionalProperties"] is False, t.name

    run(go())


def test_every_tool_can_be_called_with_its_defaults_and_returns_a_valid_structure(logs):
    jsonschema = pytest.importorskip("jsonschema")
    arguments = {"read_log": {"path": str(logs / "app.log")}, "service_status": {"unit": "cron"}}
    soft = {
        "service_status",
        "failed_units",
        "journal_tail",
        "network_interfaces",
    }  # need systemd or iproute2

    async def go():
        async with connect("--allow-dir", str(logs)) as s:
            await s.initialize()
            seen = {}
            for t in (await s.list_tools()).tools:
                res = await s.call_tool(t.name, arguments.get(t.name, {}))
                seen[t.name] = res
                if field(res, "is_error"):
                    assert t.name in soft, f"{t.name}: {text_of(res)}"
                    continue
                data = field(res, "structured_content")
                assert isinstance(data, dict), t.name
                jsonschema.validate(data, field(t, "output_schema"))
                assert json.loads(text_of(res)) == data  # the text and the structure say the same
            assert len(seen) == len(REGISTRY)

    run(go())


def test_a_log_is_read_and_its_secret_is_masked_end_to_end(logs):
    async def go():
        async with connect("--allow-dir", str(logs)) as s:
            await s.initialize()
            res = await s.call_tool("read_log", {"path": str(logs / "app.log"), "lines": 10})
            assert not field(res, "is_error")
            assert "hunter2" not in text_of(res)
            assert "password=<secret>" in text_of(res)
            res = await s.call_tool("read_log", {"path": str(logs / "app.log"), "contains": "reboot"})
            lines = field(res, "structured_content")["lines"]
            assert lines == ["reboot request from the net"]
            res = await s.call_tool("list_logs", {})
            names = [f["path"] for f in field(res, "structured_content")["files"]]
            assert str(logs / "app.log") in names

    run(go())


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("service_status", {"unit": "cron; id"}),
        ("service_status", {"unit": "--help"}),
        ("service_status", {"unit": "$(id)"}),
        ("service_status", {"unit": "a" * 300}),
        ("service_status", {}),
        ("journal_tail", {"unit": "x\ny"}),
        ("journal_tail", {"lines": 10**9}),
        ("journal_tail", {"priority": "err; id"}),
        ("top_processes", {"limit": "5"}),
        ("top_processes", {"by": "name"}),
        ("top_processes", {"sample_ms": 10**7}),
        ("listening_ports", {"protocol": "icmp"}),
        ("read_log", {"path": "/etc/passwd"}),
        ("read_log", {"path": "/etc/shadow"}),
        ("read_log", {"path": "../../../etc/passwd"}),
        ("read_log", {"path": "relative.log"}),
        ("read_log", {"path": "/proc/self/environ"}),
        ("read_log", {"path": "/dev/zero"}),
        ("read_log", {"path": "{logs}/../outside.txt"}),
        ("read_log", {"path": "{logs}/link"}),
        ("read_log", {"path": "{logs}"}),
        ("system_overview", {"unexpected": 1}),
        ("disk_usage", {"include_pseudo": "yes"}),
    ],
)
def test_bad_or_hostile_arguments_come_back_as_an_error_the_model_can_read(logs, tool, arguments):
    arguments = {k: v.replace("{logs}", str(logs)) if isinstance(v, str) else v for k, v in arguments.items()}

    async def go():
        async with connect("--allow-dir", str(logs)) as s:
            await s.initialize()
            res = await s.call_tool(tool, arguments)
            assert field(res, "is_error") is True, text_of(res)
            assert 0 < len(text_of(res)) < 1000
            # and the session is still usable afterwards
            ok = await s.call_tool("system_overview", {})
            assert not field(ok, "is_error")

    run(go())


def test_an_unknown_tool_is_a_protocol_error_not_a_crash(logs):
    async def go():
        async with connect("--allow-dir", str(logs)) as s:
            await s.initialize()
            try:
                res = await s.call_tool("rm_rf", {"path": "/"})
            except Exception as exc:  # the SDK raises McpError / MCPError for a JSON-RPC error
                assert "unknown tool" in str(exc)
            else:  # some SDK versions return it as an error result instead
                assert field(res, "is_error") and "unknown tool" in text_of(res)
            assert not field(await s.call_tool("system_overview", {}), "is_error")

    run(go())


def test_the_server_can_be_pinged_and_asked_for_things_it_does_not_have(logs):
    async def go():
        async with connect("--allow-dir", str(logs)) as s:
            await s.initialize()
            await s.send_ping()
            for ask in (s.list_resources, s.list_prompts):
                with pytest.raises(Exception, match="(?i)method not found"):
                    await ask()

    run(go())


def test_the_audit_file_records_calls_made_by_a_real_client(tmp_path, logs):
    audit = tmp_path / "audit.jsonl"

    async def go():
        async with connect("--allow-dir", str(logs), "--audit", str(audit)) as s:
            await s.initialize()
            await s.call_tool("system_overview", {})
            await s.call_tool("read_log", {"path": "/etc/passwd"})

    run(go())
    rows = [json.loads(x) for x in Path(audit).read_text().splitlines()]
    assert [(r["tool"], r["ok"]) for r in rows] == [("system_overview", True), ("read_log", False)]
    assert rows[1]["arguments"] == {"path": "/etc/passwd"}
