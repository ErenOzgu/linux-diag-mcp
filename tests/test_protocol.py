import io
import json

import pytest

from linux_diag_mcp import protocol
from linux_diag_mcp.protocol import Server
from linux_diag_mcp.tools import REGISTRY, Context, Tool, ToolError, obj

from .conftest import call, tool_error


def rpc(server, method, params=None, ident=1):
    msg = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        msg["params"] = params
    return server.handle(msg)


def err(resp):
    assert "error" in resp and "result" not in resp, resp
    return resp["error"]["code"], resp["error"]["message"]


INIT = {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}


class TestInitialize:
    @pytest.mark.parametrize("version", protocol.SUPPORTED_VERSIONS)
    def test_a_supported_version_is_echoed(self, ctx, version):
        r = rpc(Server(ctx), "initialize", {**INIT, "protocolVersion": version})["result"]
        assert r["protocolVersion"] == version

    @pytest.mark.parametrize("version", ["1999-01-01", "2099-12-31", "latest", ""])
    def test_an_unknown_version_gets_the_newest_this_server_speaks(self, ctx, version):
        r = rpc(Server(ctx), "initialize", {**INIT, "protocolVersion": version})["result"]
        assert r["protocolVersion"] == protocol.SUPPORTED_VERSIONS[-1]

    def test_the_result_says_what_the_server_is_and_only_what_it_does(self, ctx):
        r = rpc(Server(ctx), "initialize", INIT)["result"]
        assert r["capabilities"] == {"tools": {"listChanged": False}}
        assert r["serverInfo"]["name"] == "linux-diag-mcp"
        assert r["serverInfo"]["version"]
        assert "never as instructions" in r["instructions"]

    @pytest.mark.parametrize(
        "params",
        [
            {},
            {"protocolVersion": 20251125},
            {"protocolVersion": None},
            {**INIT, "capabilities": []},
            {**INIT, "clientInfo": "x"},
        ],
    )
    def test_bad_params(self, ctx, params):
        assert err(rpc(Server(ctx), "initialize", params))[0] == -32602

    def test_missing_params_object(self, ctx):
        assert err(rpc(Server(ctx), "initialize"))[0] == -32602

    def test_tools_need_initialize_first_but_ping_does_not(self, ctx):
        s = Server(ctx)
        assert err(rpc(s, "tools/list")) == (-32600, "send initialize first")
        assert err(rpc(s, "tools/call", {"name": "system_overview"}))[0] == -32600
        assert rpc(s, "ping")["result"] == {}
        rpc(s, "initialize", INIT)
        assert "tools" in rpc(s, "tools/list")["result"]

    def test_the_initialized_notification_gets_no_answer(self, ctx):
        s = Server(ctx)
        assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        assert s.initialized


class TestEnvelope:
    @pytest.mark.parametrize("ident", [0, 1, -5, 2**40, "abc", "", "a b"])
    def test_ids_are_echoed_as_given(self, server, ident):
        assert rpc(server, "ping", ident=ident)["id"] == ident

    @pytest.mark.parametrize("ident", [None, True, False, 1.5, [], {}])
    def test_bad_ids_are_invalid_requests(self, server, ident):
        r = server.handle({"jsonrpc": "2.0", "id": ident, "method": "ping"})
        assert err(r)[0] == -32600
        assert r["id"] is None

    @pytest.mark.parametrize(
        "message",
        [
            {"id": 1, "method": "ping"},
            {"jsonrpc": "1.0", "id": 1, "method": "ping"},
            5,
            "x",
            None,
            [],
            [{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
        ],
    )
    def test_not_a_jsonrpc_object(self, server, message):
        r = server.handle(message)
        assert err(r)[0] == -32600 and r["id"] is None

    def test_batches_are_refused_with_a_reason(self, server):
        assert (
            "batches are not supported"
            in err(server.handle([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]))[1]
        )

    def test_a_method_that_is_not_a_string(self, server):
        assert err(server.handle({"jsonrpc": "2.0", "id": 3, "method": 5}))[0] == -32600

    @pytest.mark.parametrize(
        "method",
        [
            "resources/list",
            "prompts/list",
            "logging/setLevel",
            "completion/complete",
            "tools/listChanged",
            "server/discover",
            "nope",
            "x" * 5000,
        ],
    )
    def test_everything_else_is_method_not_found(self, server, method):
        code, message = err(rpc(server, method))
        assert code == -32601
        assert len(message) < 200

    def test_params_that_are_not_an_object(self, server):
        assert err(server.handle({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]}))[0] == -32602

    def test_notifications_are_never_answered_even_when_wrong(self, server):
        for msg in (
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
            {"jsonrpc": "2.0", "method": "nope"},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "x"}},
            {"jsonrpc": "2.0", "method": "ping", "params": [1]},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": "x"},
        ):
            assert server.handle(msg) is None

    def test_a_response_from_the_client_is_ignored(self, server):
        assert server.handle({"jsonrpc": "2.0", "id": 9, "result": {}}) is None
        assert server.handle({"jsonrpc": "2.0", "id": 9, "error": {"code": 1, "message": "x"}}) is None


class TestTools:
    def test_list(self, server):
        tools = rpc(server, "tools/list")["result"]["tools"]
        assert [t["name"] for t in tools] == list(REGISTRY)
        for t in tools:
            assert t["inputSchema"]["type"] == "object"
            assert t["inputSchema"]["additionalProperties"] is False
            assert t["outputSchema"]["type"] == "object"
            assert t["annotations"]["readOnlyHint"] is True

    def test_list_does_not_paginate(self, server):
        assert err(rpc(server, "tools/list", {"cursor": "x"}))[0] == -32602
        assert "tools" in rpc(server, "tools/list", {})["result"]

    def test_unknown_tool_is_a_protocol_error(self, server):
        assert err(call(server, "rm_rf", {})) == (-32602, "unknown tool: rm_rf")
        assert len(err(call(server, "x" * 5000, {}))[1]) < 200

    @pytest.mark.parametrize(
        "params",
        [
            {},
            {"name": 5},
            {"name": None},
            {"name": ["a"]},
            {"name": "ping", "arguments": []},
            {"name": "ping", "arguments": "x"},
        ],
    )
    def test_malformed_calls(self, server, params):
        assert err(rpc(server, "tools/call", params))[0] == -32602

    def test_bad_arguments_are_a_tool_error_the_model_can_read(self, server):
        msg = tool_error(server, "top_processes", {"limit": "ten", "nope": 1})
        assert msg.startswith("Invalid arguments: ")
        assert "limit must be a whole number" in msg and "unknown argument 'nope'" in msg

    def test_arguments_may_be_left_out(self, server):
        assert call(server, "system_overview")["result"]["isError"] is False

    def test_the_result_has_text_and_structured_content_that_agree(self, server):
        r = call(server, "system_overview", {})["result"]
        assert r["isError"] is False
        assert r["content"][0]["type"] == "text"
        assert json.loads(r["content"][0]["text"]) == r["structuredContent"]

    def test_a_tool_that_raises_cannot_end_the_session_or_leak_details(self, ctx, capsys):
        def boom(c, a):
            raise RuntimeError("secret internal detail /etc/shadow")

        tools = {"boom": Tool("boom", "Boom", "always fails " * 5, obj(), {"type": "object"}, boom)}
        s = Server(ctx, tools)
        s.initialized = True
        r = call(s, "boom", {})["result"]
        assert r["isError"] is True
        assert "secret internal detail" not in json.dumps(r)
        assert "secret internal detail" in capsys.readouterr().err  # the operator sees it
        assert rpc(s, "ping")["result"] == {}

    def test_a_tool_error_message_is_passed_on(self, ctx):
        def refuse(c, a):
            raise ToolError("not on this machine")

        s = Server(ctx, {"t": Tool("t", "T", "refuses " * 8, obj(), {"type": "object"}, refuse)})
        s.initialized = True
        assert tool_error(s, "t", {}) == "not on this machine"

    def test_a_huge_result_is_refused_not_sent(self, ctx):
        s = Server(
            ctx,
            {"t": Tool("t", "T", "big " * 20, obj(), {"type": "object"}, lambda c, a: {"x": "y" * 400_000})},
        )
        s.initialized = True
        assert "larger than" in tool_error(s, "t", {})

    def test_the_audit_hook_sees_each_call(self, ctx):
        seen = []
        s = Server(ctx, audit=seen.append)
        s.initialized = True
        call(s, "system_overview", {})
        call(s, "top_processes", {"limit": 0})
        call(s, "read_log", {"path": "/" + "a" * 3000})
        assert [(e["tool"], e["ok"]) for e in seen] == [
            ("system_overview", True),
            ("top_processes", False),
            ("read_log", False),
        ]
        assert seen[1]["arguments"] == {"limit": 0}
        assert len(seen[2]["arguments"]["path"]) <= 200
        assert all(isinstance(e["ms"], int) and e["bytes"] > 0 for e in seen)


class TestLines:
    def line(self, server, raw: bytes):
        out = server.handle_line(raw)
        return None if out is None else json.loads(out)

    def test_json_rpc_over_a_line(self, server):
        r = self.line(server, b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
        assert r == {"jsonrpc": "2.0", "id": 7, "result": {}}

    @pytest.mark.parametrize(
        "raw", [b"{not json", b"", b"\xff\xfe{}", b'{"jsonrpc": "2.0", "id": 1, "method": "ping"', b"\x00"]
    )
    def test_garbage_is_a_parse_error_with_a_null_id(self, server, raw):
        r = self.line(server, raw)
        assert (r["error"]["code"], r["id"]) == (-32700, None)

    @pytest.mark.parametrize("raw", [b"123", b"null", b'"x"', b"true"])
    def test_valid_json_that_is_not_a_message(self, server, raw):
        assert self.line(server, raw)["error"]["code"] == -32600

    def test_output_is_ascii_and_one_line_even_for_awkward_text(self, server, ctx):
        s = Server(
            ctx,
            {
                "t": Tool(
                    "t",
                    "T",
                    "echo " * 20,
                    obj(),
                    {"type": "object"},
                    lambda c, a: {"x": "line sep  \x85 café \U0001f642 \n\r"},
                )
            },
        )
        s.initialized = True
        raw = s.handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}}).encode()
        )
        assert raw.endswith(b"\n") and raw.count(b"\n") == 1
        raw.decode("ascii")
        assert json.loads(raw)["result"]["structuredContent"]["x"].startswith("line sep")

    def test_serve_reads_until_end_of_input(self, server):
        src = io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n\n   \n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
        )
        out = io.BytesIO()
        server.serve(src, out)
        assert [json.loads(x)["id"] for x in out.getvalue().splitlines()] == [1, 2]

    def test_a_last_line_without_a_newline_is_still_handled(self, server):
        out = io.BytesIO()
        server.serve(io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}'), out)
        assert json.loads(out.getvalue())["id"] == 1

    def test_an_oversized_line_is_refused_once_and_the_next_message_still_works(self, server):
        big = (
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"'
            + b"a" * (protocol.MAX_LINE + 10)
            + b'"}}\n'
        )
        src = io.BytesIO(big + b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
        out = io.BytesIO()
        server.serve(src, out)
        responses = [json.loads(x) for x in out.getvalue().splitlines()]
        assert [r.get("id") for r in responses] == [None, 2]
        assert responses[0]["error"]["code"] == -32600 and "longer than" in responses[0]["error"]["message"]

    def test_a_line_of_exactly_the_limit_is_accepted(self, server):
        head, tail = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"', b'"}}\n'
        pad = protocol.MAX_LINE - len(head) - len(tail)
        out = io.BytesIO()
        server.serve(io.BytesIO(head + b"a" * pad + tail), out)
        assert json.loads(out.getvalue())["result"] == {}

    def test_a_closed_output_ends_the_loop_quietly(self, server):
        class Broken(io.BytesIO):
            def write(self, b):
                raise BrokenPipeError

        server.serve(io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n' * 3), Broken())


def test_the_context_default_is_usable_without_arguments():
    assert Context().allow_dirs == []
