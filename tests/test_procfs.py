import os
import shutil
import subprocess
from pathlib import Path

import pytest

from linux_diag_mcp import procfs

from .conftest import make_proc, make_sys, stat_line


@pytest.fixture
def proc(tmp_path):
    return make_proc(tmp_path)


class TestMade:
    def test_meminfo_is_in_bytes(self, proc):
        m = procfs.meminfo(proc)
        assert m["MemTotal"] == 16000000 * 1024
        assert m["MemAvailable"] == 8000000 * 1024
        assert m["HugePages_Total"] == 0

    def test_a_meminfo_without_memtotal_is_an_error(self, tmp_path):
        (tmp_path / "meminfo").write_text("MemFree: 1 kB\n")
        with pytest.raises(procfs.ProcError, match="MemTotal"):
            procfs.meminfo(tmp_path)

    def test_uptime_and_load(self, proc):
        assert procfs.uptime_seconds(proc) == 12345.67
        assert procfs.loadavg(proc) == (0.5, 1.0, 2.0)

    def test_garbage_in_those_files_is_a_proc_error(self, tmp_path):
        (tmp_path / "uptime").write_text("nope\n")
        (tmp_path / "loadavg").write_text("\n")
        with pytest.raises(procfs.ProcError):
            procfs.uptime_seconds(tmp_path)
        with pytest.raises(procfs.ProcError):
            procfs.loadavg(tmp_path)

    def test_a_missing_file_is_a_proc_error_not_a_crash(self, tmp_path):
        with pytest.raises(procfs.ProcError, match="cannot read"):
            procfs.meminfo(tmp_path)

    def test_mounts_unescape_spaces(self, proc):
        points = {m.point: m for m in procfs.mounts(proc)}
        assert "/mnt/with space" in points
        assert points["/mnt/with space"].options == ["ro"]
        assert points["/"].fstype == "ext4"

    def test_ipv4_listeners_are_decoded(self, proc):
        socks = {(s.address, s.port): s for s in procfs.sockets("tcp", proc)}
        assert socks[("0.0.0.0", 80)].state == "0A"
        assert socks[("127.0.0.1", 631)].inode == 2222
        assert socks[("127.0.0.1", 50000)].state == "01"

    def test_ipv6_addresses_are_decoded(self, proc):
        socks = {(s.address, s.port): s for s in procfs.sockets("tcp6", proc)}
        assert ("::1", 5432) in socks
        assert ("::", 22) in socks

    def test_a_missing_protocol_file_means_no_sockets(self, tmp_path):
        assert procfs.sockets("tcp6", tmp_path) == []

    def test_malformed_socket_lines_are_skipped(self, tmp_path):
        (tmp_path / "net").mkdir()
        (tmp_path / "net" / "tcp").write_text("header\nshort line\n 0: ZZZZ:0050 x 0A 0 0 0 0 0 5\n")
        assert procfs.sockets("tcp", tmp_path) == []

    def test_socket_owners_follow_the_fd_links(self, proc):
        owners = procfs.socket_owners(proc)
        assert owners[1111] == (1, "init")
        assert owners[2222] == (42, "web (worker) 2")
        assert owners[5555] == (42, "web (worker) 2")
        assert 3333 not in owners

    def test_processes_are_parsed_even_with_parentheses_and_spaces_in_the_name(self, proc):
        by = {p.pid: p for p in procfs.processes(proc)}
        assert by[42].name == "web (worker) 2"
        assert (by[42].cpu_ticks, by[42].threads, by[42].state) == (2500, 4, "S")
        assert by[42].rss_bytes == 40960 * os.sysconf("SC_PAGE_SIZE")
        assert by[1].ppid == 1

    def test_the_owner_is_the_real_uid_from_status_not_the_owner_of_the_directory(self, proc):
        # a process that is not dumpable has a /proc/PID owned by root; status still says who it belongs to
        (proc / "42" / "status").write_text("Name:\tweb\nUid:\t1234\t0\t0\t0\nGid:\t1234\t1234\t1234\t1234\n")
        by = {p.pid: p for p in procfs.processes(proc)}
        assert by[42].uid == 1234
        assert by[1].uid == os.stat(proc / "1").st_uid  # no status file: the directory's owner

    @pytest.mark.parametrize("text", ["", "Name:\tx\n", "Uid:\n", "Uid:\tabc\t0\t0\t0\n", "\x00\xff"])
    def test_a_status_file_that_cannot_be_read_falls_back_to_the_directory_owner(self, proc, text):
        (proc / "42" / "status").write_text(text, errors="replace")
        assert {p.pid: p for p in procfs.processes(proc)}[42].uid == os.stat(proc / "42").st_uid

    def test_a_process_that_vanishes_is_skipped(self, proc):
        shutil.rmtree(proc / "77" / "fd")
        (proc / "77" / "stat").unlink()
        assert {p.pid for p in procfs.processes(proc)} == {1, 42}

    def test_a_bad_stat_file_is_skipped(self, proc):
        (proc / "77" / "stat").write_text("garbage")
        assert {p.pid for p in procfs.processes(proc)} == {1, 42}

    def test_stat_name_with_a_closing_parenthesis_and_a_fake_field(self):
        line = stat_line(5, "a) S 99 (b")
        name, state, ppid, ticks, threads, start, rss = procfs._parse_stat(line)
        assert (name, state, ppid) == ("a) S 99 (b", "S", 1)

    def test_cmdline_is_joined_with_spaces(self, proc):
        assert procfs.cmdline(1, proc) == "/usr/bin/init --password=hunter2 --port 80"
        assert procfs.cmdline(9999, proc) == ""

    def test_interfaces(self, tmp_path):
        ifs = {i["name"]: i for i in procfs.interfaces(make_sys(tmp_path))}
        assert ifs["eth0"]["mtu"] == 1500
        assert ifs["eth0"]["mac"] == "02:00:00:00:00:01"
        assert ifs["eth0"]["rx_dropped"] == 1
        assert procfs.interfaces(tmp_path / "nothing") == []

    def test_unknown_uid_is_shown_as_a_number(self):
        assert procfs.user_name(4_000_000_000) == "4000000000"
        assert procfs.user_name(0) == "root"


# ---- the real /proc, against the programs that read the same numbers --------------------------------------


def run(*argv):
    return subprocess.run(
        argv, capture_output=True, text=True, check=True, env={"LC_ALL": "C", "PATH": os.environ["PATH"]}
    ).stdout


@pytest.mark.skipif(not Path("/proc/meminfo").exists(), reason="no /proc")
class TestLive:
    @pytest.mark.skipif(not shutil.which("free"), reason="no free")
    def test_memory_matches_free(self):
        line = next(ln for ln in run("free", "-b").splitlines() if ln.startswith("Mem:")).split()
        total, available = int(line[1]), int(line[6])
        m = procfs.meminfo()
        assert m["MemTotal"] == total
        assert abs(m["MemAvailable"] - available) < 0.02 * total

    @pytest.mark.skipif(not shutil.which("ss"), reason="no ss")
    def test_a_listener_we_open_is_found_with_its_pid(self):
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        try:
            ours = [x for x in procfs.sockets("tcp") if x.port == port and x.state == procfs.TCP_LISTEN]
            assert len(ours) == 1
            assert ours[0].address == "127.0.0.1"
            assert procfs.socket_owners()[ours[0].inode][0] == os.getpid()
            assert f":{port} " in run("ss", "-ltn") + " "
        finally:
            s.close()

    @pytest.mark.skipif(not shutil.which("ss"), reason="no ss")
    def test_the_listening_tcp_ports_are_the_ones_ss_shows(self):
        ours = {
            (s.address, s.port)
            for k in ("tcp", "tcp6")
            for s in procfs.sockets(k)
            if s.state == procfs.TCP_LISTEN
        }
        theirs = set()
        for line in run("ss", "-ltnH").splitlines():
            local = line.split()[3]
            host, _, port = local.rpartition(":")
            host = host.strip("[]").split("%")[0]
            theirs.add((host if host != "*" else "0.0.0.0", int(port)))
        # ss prints "*" for both families; compare the ports, which cannot be confused
        assert {p for _, p in ours} == {p for _, p in theirs}

    @pytest.mark.skipif(not shutil.which("ps"), reason="no ps")
    def test_our_own_process_matches_ps(self):
        me = next(p for p in procfs.processes() if p.pid == os.getpid())
        rss_kb = int(run("ps", "-o", "rss=", "-p", str(os.getpid())).strip())
        assert abs(me.rss_bytes / 1024 - rss_kb) < 4096
        assert me.ppid == int(run("ps", "-o", "ppid=", "-p", str(os.getpid())).strip())
        assert me.threads == int(run("ps", "-o", "nlwp=", "-p", str(os.getpid())).strip())

    def test_every_process_listed_has_a_sane_shape(self):
        procs = procfs.processes()
        assert any(p.pid == 1 for p in procs)
        assert all(p.threads >= 1 and p.rss_bytes >= 0 and p.cpu_ticks >= 0 for p in procs)
