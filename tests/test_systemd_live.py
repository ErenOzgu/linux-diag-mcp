"""The systemd tools against a real systemd, checked with systemctl itself.

This file is skipped on a machine that was not booted with systemd (a container, most sandboxes) and where
``sudo`` cannot be used without a password. It runs in CI on the GitHub-hosted Ubuntu runner, which has
both. It starts two throw-away transient units with ``systemd-run`` (one that fails, one that logs a line)
and removes them afterwards. Nothing is installed and no file is written.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid

import pytest

from linux_diag_mcp import diag  # noqa: F401  (registers the tools)
from linux_diag_mcp.tools import REGISTRY, Context

booted_with_systemd = os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None
pytestmark = pytest.mark.skipif(not booted_with_systemd, reason="this machine was not booted with systemd")


def call(name: str, **args):
    return REGISTRY[name].handler(Context(), args)


def run(*argv: str, sudo: bool = False) -> subprocess.CompletedProcess:
    if sudo and os.geteuid() != 0:
        argv = ("sudo", "-n", *argv)
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def can_sudo() -> bool:
    return os.geteuid() == 0 or run("sudo", "-n", "true").returncode == 0


def systemctl_show(unit: str, prop: str) -> str:
    return run("systemctl", "show", "--value", f"--property={prop}", unit).stdout.strip()


def wait_until(check, seconds: float = 15.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.2)
    return False


class TestAnAlwaysPresentService:
    def test_journald_is_reported_as_systemctl_reports_it(self):
        got = call("service_status", unit="systemd-journald")
        assert got["found"] is True
        assert got["unit"] == "systemd-journald.service"
        assert got["load_state"] == systemctl_show("systemd-journald.service", "LoadState") == "loaded"
        assert got["active_state"] == systemctl_show("systemd-journald.service", "ActiveState") == "active"
        assert got["sub_state"] == systemctl_show("systemd-journald.service", "SubState")
        assert got["main_pid"] == int(systemctl_show("systemd-journald.service", "MainPID")) > 0
        assert got["fragment_path"] == systemctl_show("systemd-journald.service", "FragmentPath")
        assert got["description"] == systemctl_show("systemd-journald.service", "Description")

    def test_the_suffix_is_optional_and_a_wrong_suffix_is_not_the_same_unit(self):
        assert call("service_status", unit="systemd-journald.service")["active_state"] == "active"
        assert call("service_status", unit="systemd-journald.socket")["unit"] == "systemd-journald.socket"

    def test_a_unit_that_does_not_exist_is_reported_as_not_found(self):
        got = call("service_status", unit="there-is-no-such-unit-" + uuid.uuid4().hex[:8])
        assert got["found"] is False
        assert got["load_state"] == "not-found"
        assert got["active_state"] == "inactive"

    def test_pid_one_is_systemd(self):
        assert call("service_status", unit="init.scope")["found"] is True


@pytest.mark.skipif(not booted_with_systemd or not can_sudo(), reason="needs passwordless sudo")
class TestTransientUnits:
    @pytest.fixture
    def failing_unit(self):
        name = "lmcp-fail-" + uuid.uuid4().hex[:8]
        r = run(
            "systemd-run",
            f"--unit={name}",
            "--description=linux-diag-mcp test: always fails",
            "/bin/false",
            sudo=True,
        )
        assert r.returncode == 0, r.stderr
        assert wait_until(lambda: run("systemctl", "is-failed", name).stdout.strip() == "failed"), (
            "unit never failed"
        )
        yield name
        run("systemctl", "reset-failed", name, sudo=True)

    @pytest.fixture
    def talking_unit(self):
        name = "lmcp-talk-" + uuid.uuid4().hex[:8]
        marker = "marker-" + uuid.uuid4().hex
        script = f"echo '{marker} info line'; echo '{marker} password=hunter2 leaked?'; echo '<3>{marker} error line'"
        r = run("systemd-run", f"--unit={name}", "--collect", "sh", "-c", script, sudo=True)
        assert r.returncode == 0, r.stderr
        time.sleep(1.5)
        run("journalctl", "--sync", sudo=True)
        yield name, marker

    def test_a_failed_unit_is_listed_and_its_status_says_why(self, failing_unit):
        listed = call("failed_units")
        assert any(u["unit"] == failing_unit + ".service" for u in listed["units"]), listed
        assert listed["count"] >= 1
        row = next(u for u in listed["units"] if u["unit"] == failing_unit + ".service")
        assert (row["load"], row["active"], row["sub"]) == ("loaded", "failed", "failed")
        assert "always fails" in row["description"]
        status = call("service_status", unit=failing_unit)
        assert status["active_state"] == "failed"
        assert status["result"] == "exit-code"
        assert status["exec_main_status"] == 1
        assert status["restarts"] in (0, None)

    def test_the_list_matches_systemctl_failed(self, failing_unit):
        out = run("systemctl", "list-units", "--failed", "--no-legend", "--plain", "--full").stdout
        theirs = {line.split()[0] for line in out.splitlines() if line.strip()}
        mine = {u["unit"] for u in call("failed_units")["units"]}
        assert theirs <= mine | {"(more)"}
        assert failing_unit + ".service" in mine

    def test_a_reset_unit_leaves_the_list(self, failing_unit):
        run("systemctl", "reset-failed", failing_unit, sudo=True)
        assert all(u["unit"] != failing_unit + ".service" for u in call("failed_units")["units"])

    def test_the_journal_lines_of_one_unit_are_found_and_the_secret_is_masked(self, talking_unit):
        name, marker = talking_unit
        if run("journalctl", "--no-pager", "-n", "1", "--unit", name + ".service").returncode != 0:
            pytest.skip("this user may not read the journal")
        got = call("journal_tail", unit=name, lines=50)
        mine = [x for x in got["lines"] if marker in x]
        if not mine:
            pytest.skip("this user sees no lines of system units in the journal")
        assert len(mine) == 3, got
        assert not any("hunter2" in x for x in mine)
        assert any("password=<secret>" in x for x in mine)
        assert got["redacted_lines"] >= 1
        assert all(len(x) < 2000 for x in mine)
        assert any(x.startswith("20") for x in mine)  # --output=short-iso starts with the year

    def test_the_priority_filter_keeps_the_error_and_drops_the_info(self, talking_unit):
        name, marker = talking_unit
        got = call("journal_tail", unit=name, priority="err", lines=50)
        lines = [x for x in got["lines"] if marker in x]
        if not lines:
            pytest.skip("this user sees no lines of system units in the journal")
        assert len(lines) == 1 and "error line" in lines[0]

    def test_since_minutes_bounds_the_search(self, talking_unit):
        name, marker = talking_unit
        recent = call("journal_tail", unit=name, since_minutes=5, lines=50)["lines"]
        if not any(marker in x for x in recent):
            pytest.skip("this user sees no lines of system units in the journal")
        assert call("journal_tail", unit=name, since_minutes=1, lines=1)["count"] <= 1


class TestTheJournalIsOptional:
    def test_the_whole_journal_can_be_tailed_or_the_refusal_is_clear(self):
        try:
            got = call("journal_tail", lines=5)
        except Exception as exc:
            assert "journalctl" in str(exc)
        else:
            assert got["count"] <= 5
