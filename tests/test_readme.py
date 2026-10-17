"""The README makes claims about the code and quotes its output. These keep both honest.

``python tests/test_readme.py`` prints the tools table, to paste between the markers in README.md.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from linux_diag_mcp import diag  # noqa: E402,F401
from linux_diag_mcp.cli import build_parser, parse_args  # noqa: E402
from linux_diag_mcp.tools import REGISTRY  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""


def first_sentence(text: str) -> str:
    return re.split(r"(?<=[.])\s", text, maxsplit=1)[0]


def tools_table() -> str:
    rows = ["| Tool | Arguments | What it returns |", "|---|---|---|"]
    for t in REGISTRY.values():
        d = t.definition()
        props = d["inputSchema"].get("properties", {})
        required = set(d["inputSchema"].get("required", []))
        shown = ", ".join(f"`{k}`" + ("" if k in required else "?") for k in props) or "none"
        rows.append(f"| `{d['name']}` | {shown} | {first_sentence(d['description'])} |")
    return "\n".join(rows)


def test_the_tools_table_is_what_the_code_says():
    m = re.search(r"<!-- tools:start -->\n(.*?)\n<!-- tools:end -->", README, re.DOTALL)
    assert m, "the markers are missing"
    assert m.group(1) == tools_table()


def test_every_tool_has_a_description_a_title_and_a_schema_that_forbids_extra_arguments():
    for t in REGISTRY.values():
        assert t.description.strip() and t.title.strip(), t.name
        assert t.input_schema["additionalProperties"] is False, t.name
        assert len(t.description) < 700, f"{t.name}: a description is read by the model on every turn"


def options() -> set[str]:
    return {
        o for action in build_parser()._actions for o in action.option_strings if o not in ("-h", "--help")
    }  # noqa: SLF001


def test_every_option_is_in_the_readme_and_every_documented_option_exists():
    real = options()
    assert real >= {"--allow-dir", "--audit", "--list-tools", "--version"}
    missing = [o for o in sorted(real) if f"`{o}" not in README]
    assert not missing, f"not documented: {missing}"
    documented = set(re.findall(r"^\| `(--[a-z-]+)", README, re.MULTILINE))
    assert documented and documented <= real


def test_the_environment_variable_in_the_readme_is_the_one_the_code_reads():
    assert "LINUX_DIAG_MCP_ALLOW_DIRS" in README
    assert "LINUX_DIAG_MCP_ALLOW_DIRS" in (ROOT / "linux_diag_mcp" / "cli.py").read_text()


def json_blocks() -> list[dict]:
    return [json.loads(b) for b in re.findall(r"```json\n(.*?)```", README, re.DOTALL)]


def test_the_client_configuration_in_the_readme_is_valid_and_its_arguments_parse():
    configs = [b for b in json_blocks() if "mcpServers" in b]
    assert configs, "no client configuration block"
    for cfg in configs:
        for name, server in cfg["mcpServers"].items():
            assert server["command"] and isinstance(server["args"], list), name
            args = server["args"]
            if server["command"] == "ssh":  # the remote command starts after the host name
                args = args[args.index("linux-diag-mcp") + 1 :]
            parse_args(args)  # raises SystemExit on an option the server does not have


def test_the_shell_commands_in_the_readme_use_real_options():
    for line in re.findall(r"^(?:\$ )?(claude mcp add .*)$", README, re.MULTILINE):
        rest = line.split(" -- ", 1)[1].split()
        if rest[0] == "ssh":
            rest = rest[rest.index("linux-diag-mcp") :]
        assert rest[0] == "linux-diag-mcp"
        parse_args(rest[1:])


def quoted(name: str) -> str:
    m = re.search(rf"<!-- {name}:start -->\n```\w+\n(.*?)\n```\n<!-- {name}:end -->", README, re.DOTALL)
    assert m, f"the {name} markers are missing"
    return m.group(1)


def test_the_journal_result_quoted_in_the_readme_is_in_the_committed_transcript():
    assert quoted("excerpt") in (ROOT / "examples" / "transcript.md").read_text(encoding="utf-8")


def test_the_error_messages_quoted_in_the_readme_are_the_ones_the_session_produced():
    transcript = (ROOT / "examples" / "transcript.md").read_text(encoding="utf-8")
    lines = quoted("errors").splitlines()
    assert len(lines) >= 3
    for line in lines:
        assert line in transcript, line


def test_the_hand_typed_session_in_the_readme_works():
    block = next(b for b in re.findall(r"```sh\n(.*?)```", README, re.DOTALL) if "printf" in b)
    assert block.rstrip().endswith("| linux-diag-mcp")
    command = block.rstrip()[: -len("linux-diag-mcp")] + f"{sys.executable} -m linux_diag_mcp"
    out = subprocess.run(["sh", "-c", command], capture_output=True, text=True, cwd=ROOT, timeout=30).stdout
    replies = [json.loads(x) for x in out.splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[1]["result"]["structuredContent"]["hostname"]


def test_the_transcript_is_up_to_date():
    r = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "make_transcript.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


def test_list_tools_prints_what_the_readme_table_is_built_from():
    out = subprocess.run(
        [sys.executable, "-m", "linux_diag_mcp", "--list-tools"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    ).stdout
    assert [t["name"] for t in json.loads(out)] == list(REGISTRY)


@pytest.mark.parametrize("path", re.findall(r"\]\(((?!https?:|#)[^)]+)\)", README))
def test_relative_links_in_the_readme_point_at_files_that_exist(path):
    assert (ROOT / path.split("#")[0]).exists(), path


if __name__ == "__main__":
    print(tools_table())
