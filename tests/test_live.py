"""The tools against the real machine, checked with the programs an administrator would use instead.

Everything else in the test suite feeds the tools a made-up /proc. Here the numbers come from the running
kernel and are compared with ``free``, ``df``, ``ss``, ``ps``, ``ip`` and ``uname``, so a misreading of a
real /proc file (a unit, an off-by-1024, a column that moved) cannot hide behind a fixture that shares the
same mistake. Values that change from one moment to the next are compared with a tolerance, and a test is
skipped, not failed, where the comparison program does not exist.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

from linux_diag_mcp import diag  # noqa: F401  (registers the tools)
from linux_diag_mcp.tools import REGISTRY, Context

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")


def call(name: str, **args):
    return REGISTRY[name].handler(Context(), args)


def sh(*argv: str, env: dict[str, str] | None = None) -> str:
    if shutil.which(argv[0]) is None:
        pytest.skip(f"{argv[0]} is not installed")
    out = subprocess.run(argv, capture_output=True, text=True, timeout=20, env={**os.environ, **(env or {})})
    if out.returncode != 0:
        pytest.skip(f"{' '.join(argv)} failed: {out.stderr.strip()[:100]}")
    return out.stdout


class TestSystemOverview:
    def test_it_agrees_with_free_uname_and_hostname(self):
        got = call("system_overview")
        mem = [line.split() for line in sh("free", "-b").splitlines() if line.startswith("Mem:")][0]
        assert got["memory"]["total_bytes"] == int(mem[1])
        assert abs(got["memory"]["available_bytes"] - int(mem[6])) < max(0.05 * int(mem[1]), 200 * 2**20)
        assert got["kernel"] == sh("uname", "-r").strip()
        assert got["architecture"] == sh("uname", "-m").strip()
        assert got["hostname"] == sh("hostname").strip()
        assert got["cpus"] == int(sh("nproc").strip())

    def test_the_boot_time_agrees_with_uptime_s(self):
        got = call("system_overview")
        said = sh("uptime", "-s", env={"TZ": "UTC"}).strip()
        booted = (
            time.mktime(time.strptime(said, "%Y-%m-%d %H:%M:%S"))
            - time.mktime(time.gmtime(0))
            + time.timezone
        )
        # uptime -s reads the same clocks, so only a unit or time-zone mistake can make these differ
        mine = (
            time.mktime(time.strptime(got["booted_at"], "%Y-%m-%dT%H:%M:%SZ"))
            - time.mktime(time.gmtime(0))
            + time.timezone
        )
        assert abs(mine - booted) <= 3

    def test_the_load_agrees_with_the_c_library(self):
        got = call("system_overview")["load"]
        one, five, fifteen = os.getloadavg()
        assert abs(got["m15"] - fifteen) < 1.0
        assert abs(got["m5"] - five) < 2.0
        assert got["m1"] >= 0 and one >= 0

    def test_memory_adds_up(self):
        m = call("system_overview")["memory"]
        assert m["used_bytes"] + m["available_bytes"] == m["total_bytes"]
        assert 0 <= m["used_percent"] <= 100
        assert m["swap_used_bytes"] <= m["swap_total_bytes"]


class TestDiskUsage:
    def test_the_root_file_system_agrees_with_df(self):
        rows = {f["mount"]: f for f in call("disk_usage")["filesystems"]}
        assert "/" in rows
        line = sh("df", "-B1", "--output=size,avail,fstype,itotal", "/").splitlines()[1].split()
        mine = rows["/"]
        assert mine["total_bytes"] == int(line[0])
        assert abs(mine["available_bytes"] - int(line[1])) < 200 * 2**20  # other programs write meanwhile
        assert mine["fstype"] == line[2]
        assert mine["inodes_total"] == int(line[3])
        assert 0 <= mine["used_percent"] <= 100

    def test_every_mount_it_shows_is_one_df_knows(self):
        known = set(sh("df", "-a", "--output=target").splitlines()[1:])
        shown = {f["mount"] for f in call("disk_usage")["filesystems"]}
        assert shown and shown <= {k.strip() for k in known}

    def test_pseudo_file_systems_are_left_out_unless_asked_for(self):
        plain = {f["fstype"] for f in call("disk_usage")["filesystems"]}
        every = {f["fstype"] for f in call("disk_usage", include_pseudo=True)["filesystems"]}
        assert not plain & {"proc", "sysfs", "cgroup2", "devpts"}
        assert "proc" in every


@pytest.fixture
def busy_child():
    child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    time.sleep(0.3)
    yield child
    child.kill()
    child.wait()


@pytest.fixture
def fat_child():
    code = "import time; b = bytearray(150 * 2**20); b[::4096] = b'x' * len(b[::4096]); time.sleep(60)"
    child = subprocess.Popen([sys.executable, "-c", code])
    time.sleep(1.0)
    yield child
    child.kill()
    child.wait()


class TestTopProcesses:
    def test_a_busy_loop_is_found_and_measured_like_ps_would(self, busy_child):
        rows = call("top_processes", by="cpu", limit=50, sample_ms=800)["processes"]
        mine = next((r for r in rows if r["pid"] == busy_child.pid), None)
        assert mine is not None, rows
        assert 60 <= mine["cpu_percent"] <= 130  # one core, give or take scheduling
        assert mine["state"] in ("R", "S")
        assert mine["user"] == sh("ps", "-o", "user:32=", "-p", str(busy_child.pid)).strip()
        assert mine["name"] == sh("ps", "-o", "comm=", "-p", str(busy_child.pid)).strip()

    def test_the_busiest_process_comes_first(self, busy_child):
        rows = call("top_processes", by="cpu", limit=3, sample_ms=800)["processes"]
        assert [r["cpu_percent"] for r in rows] == sorted((r["cpu_percent"] for r in rows), reverse=True)
        assert rows[0]["cpu_percent"] >= 50

    def test_resident_memory_agrees_with_ps(self, fat_child):
        rows = call("top_processes", by="memory", limit=50)["processes"]
        mine = next((r for r in rows if r["pid"] == fat_child.pid), None)
        assert mine is not None, [r["pid"] for r in rows]
        ps_kib = int(sh("ps", "-o", "rss=", "-p", str(fat_child.pid)).strip())
        assert abs(mine["rss_bytes"] - ps_kib * 1024) < 0.1 * mine["rss_bytes"]
        assert mine["rss_bytes"] >= 140 * 2**20

    def test_the_command_line_is_left_out_unless_asked_for(self, busy_child):
        plain = call("top_processes", by="cpu", limit=50, sample_ms=300)["processes"]
        assert all("cmdline" not in r for r in plain)
        with_cmd = call("top_processes", by="cpu", limit=50, sample_ms=300, include_cmdline=True)["processes"]
        mine = next(r for r in with_cmd if r["pid"] == busy_child.pid)
        assert "while True: pass" in mine["cmdline"]

    def test_the_process_count_is_close_to_ps(self):
        n = len(sh("ps", "-e", "-o", "pid=").split())
        assert abs(call("top_processes", by="memory", limit=1)["total_processes"] - n) <= 12


def ss_ports(kind: str) -> set[int]:
    rows = sh("ss", "-H", f"-l{kind}n").splitlines()
    ports = set()
    for row in rows:
        local = row.split()[3]
        ports.add(int(local.rsplit(":", 1)[1]))
    return ports


class TestListeningPorts:
    def test_a_tcp_and_a_udp_socket_opened_here_are_found_with_their_owner(self):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            udp.bind(("127.0.0.1", 0))
            t_port, u_port = tcp.getsockname()[1], udp.getsockname()[1]
            rows = call("listening_ports", limit=500)["listeners"]
        mine_tcp = [r for r in rows if r["port"] == t_port and r["protocol"] == "tcp"]
        mine_udp = [r for r in rows if r["port"] == u_port and r["protocol"] == "udp"]
        assert mine_tcp and mine_udp, rows
        assert mine_tcp[0]["address"] == "127.0.0.1" and mine_udp[0]["address"] == "127.0.0.1"
        assert mine_tcp[0]["pid"] == os.getpid() and mine_udp[0]["pid"] == os.getpid()
        assert mine_tcp[0]["process"] == sh("ps", "-o", "comm=", "-p", str(os.getpid())).strip()

    def test_an_ipv6_listener_is_found_where_the_machine_has_ipv6(self):
        if not os.path.exists("/proc/net/tcp6"):
            pytest.skip("no IPv6 on this machine")
        with socket.socket(socket.AF_INET6) as tcp:
            try:
                tcp.bind(("::1", 0))
            except OSError:
                pytest.skip("cannot bind ::1")
            tcp.listen()
            port = tcp.getsockname()[1]
            rows = call("listening_ports", protocol="tcp", limit=500)["listeners"]
        assert any(r["port"] == port and r["address"] == "::1" for r in rows), rows

    def test_the_tcp_ports_are_the_ones_ss_lists(self):
        before = ss_ports("t")
        mine = {r["port"] for r in call("listening_ports", protocol="tcp", limit=500)["listeners"]}
        after = ss_ports("t")
        assert (before & after) <= mine <= (before | after)

    def test_the_udp_ports_are_the_ones_ss_lists(self):
        before = ss_ports("u")
        mine = {r["port"] for r in call("listening_ports", protocol="udp", limit=500)["listeners"]}
        after = ss_ports("u")
        assert (before & after) <= mine <= (before | after)


class TestNetworkInterfaces:
    def test_the_names_and_loopback_address_agree_with_ip(self):
        out = sh("ip", "-o", "link")
        names = {m.group(1).split("@")[0] for m in re.finditer(r"^\d+: (\S+?):", out, re.M)}
        got = call("network_interfaces")["interfaces"]
        assert {i["name"] for i in got} == names
        lo = next(i for i in got if i["name"] == "lo")
        assert any(a["address"] == "127.0.0.1" and a["prefix_length"] == 8 for a in lo["addresses"])

    def test_counters_only_grow(self):
        a = {i["name"]: i["rx_bytes"] for i in call("network_interfaces")["interfaces"]}
        b = {i["name"]: i["rx_bytes"] for i in call("network_interfaces")["interfaces"]}
        assert all(b[k] >= v for k, v in a.items() if k in b)
