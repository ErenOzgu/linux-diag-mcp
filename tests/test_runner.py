"""The one place a program is started. These use the real Runner and real (harmless) programs."""

from __future__ import annotations

import select
import subprocess
import sys
import textwrap

import pytest

from linux_diag_mcp.runner import ENV, MAX_BYTES, NotInstalled, RunFailed, Runner


def test_a_missing_program_is_reported_as_not_installed():
    with pytest.raises(NotInstalled):
        Runner().run(["definitely-not-a-program-linux-diag-mcp"])


def test_a_program_that_runs_too_long_is_stopped_and_reported():
    with pytest.raises(RunFailed, match="longer than"):
        Runner().run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)


def test_the_exit_code_and_both_streams_come_back():
    r = Runner().run(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"]
    )
    assert (r.returncode, r.stdout.strip(), r.stderr.strip()) == (3, "out", "err")
    assert r.truncated is False


def test_output_beyond_the_limit_is_cut_and_marked():
    r = Runner().run([sys.executable, "-c", f"print('x' * {MAX_BYTES * 2})"])
    assert len(r.stdout) == MAX_BYTES
    assert r.truncated is True


def test_arguments_are_never_interpreted_by_a_shell():
    hostile = "a; echo INJECTED $(id) `id` | cat > /dev/null && echo INJECTED"
    r = Runner().run([sys.executable, "-c", "import sys; print(sys.argv[1])", hostile])
    assert r.stdout.strip() == hostile


def test_the_environment_is_the_small_fixed_one_not_the_callers():
    code = "import json, os; print(json.dumps(dict(os.environ)))"
    import json

    env = json.loads(Runner().run([sys.executable, "-c", code]).stdout)
    assert env == ENV
    assert "HOME" not in env and "LD_PRELOAD" not in env


def test_a_program_never_gets_the_servers_standard_input():
    """The server's stdin is the protocol stream. A child that read it would eat the client's messages."""
    code = textwrap.dedent(
        """
        from linux_diag_mcp.runner import Runner
        r = Runner().run(["cat"], timeout=5)
        print(r.returncode, repr(r.stdout))
        """
    )
    p = subprocess.Popen(
        [sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        # stdin stays open and carries data. A child that inherited it would wait for more, or print it back.
        assert p.stdin is not None and p.stdout is not None
        p.stdin.write("the protocol stream\n")
        p.stdin.flush()
        ready, _, _ = select.select([p.stdout], [], [], 15)
        assert ready, "the child program is waiting on the server's standard input"
        out = p.stdout.readline()
    finally:
        p.kill()
        p.wait()
    assert out.strip() == "0 ''"
