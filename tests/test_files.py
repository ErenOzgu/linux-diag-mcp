import os
import socket
import stat

import pytest

from linux_diag_mcp import files
from linux_diag_mcp.files import Refused


@pytest.fixture
def roots(logdir):
    return [logdir]


def put(logdir, name, text="line 1\nline 2\nline 3\n"):
    path = logdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def read(path, roots, lines=100, contains=None):
    real = files.resolve(str(path), roots)
    fd = files.open_checked(real, roots)
    try:
        return files.tail(fd, lines, contains)
    finally:
        os.close(fd)


class TestResolve:
    def test_a_file_inside_is_accepted(self, logdir, roots):
        assert files.resolve(str(put(logdir, "a.log")), roots) == logdir / "a.log"

    @pytest.mark.parametrize("bad", ["", "relative.log", "logs/a.log", "./a.log", "~/a.log", "$HOME/a.log"])
    def test_only_absolute_paths_are_taken(self, bad, roots):
        with pytest.raises(Refused, match="absolute path"):
            files.resolve(bad, roots)

    def test_a_nul_byte_or_a_huge_path_is_refused(self, roots):
        for bad in ("/var/log/a\0.log", "/" + "a" * 5000):
            with pytest.raises(Refused, match="not a usable path"):
                files.resolve(bad, roots)

    @pytest.mark.parametrize("bad", ["/etc/passwd", "/etc/shadow", "/proc/self/environ", "/root/.ssh/id_rsa"])
    def test_system_files_are_outside(self, bad, roots):
        with pytest.raises(Refused, match="outside the allowed"):
            files.resolve(bad, roots)

    def test_dot_dot_cannot_climb_out(self, logdir, roots):
        for bad in (
            f"{logdir}/../etc/passwd",
            f"{logdir}/sub/../../../../etc/passwd",
            f"{logdir}/..",
            f"{logdir}//../x",
        ):
            with pytest.raises(Refused, match="outside"):
                files.resolve(bad, roots)

    def test_dot_dot_that_stays_inside_is_fine(self, logdir, roots):
        put(logdir, "sub/a.log")
        assert files.resolve(f"{logdir}/sub/../sub/a.log", roots) == logdir / "sub" / "a.log"

    def test_a_directory_named_like_the_root_with_a_suffix_is_outside(self, logdir, roots):
        sibling = logdir.parent / (logdir.name + "-private")
        sibling.mkdir()
        (sibling / "secret.log").write_text("x")
        with pytest.raises(Refused, match="outside"):
            files.resolve(str(sibling / "secret.log"), roots)

    def test_a_symlink_to_the_outside_is_refused(self, logdir, roots, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        os.symlink(outside, logdir / "link.log")
        with pytest.raises(Refused, match="outside"):
            files.resolve(str(logdir / "link.log"), roots)

    def test_a_symlinked_directory_to_the_outside_is_refused(self, logdir, roots, tmp_path):
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "elsewhere" / "x.log").write_text("secret")
        os.symlink(tmp_path / "elsewhere", logdir / "dir")
        with pytest.raises(Refused, match="outside"):
            files.resolve(str(logdir / "dir" / "x.log"), roots)

    def test_a_chain_of_symlinks_is_followed_all_the_way(self, logdir, roots, tmp_path):
        outside = tmp_path / "o.txt"
        outside.write_text("x")
        os.symlink(outside, logdir / "b")
        os.symlink(logdir / "b", logdir / "a")
        with pytest.raises(Refused, match="outside"):
            files.resolve(str(logdir / "a"), roots)

    def test_a_symlink_that_stays_inside_is_fine(self, logdir, roots):
        put(logdir, "real.log")
        os.symlink(logdir / "real.log", logdir / "alias.log")
        assert files.resolve(str(logdir / "alias.log"), roots) == logdir / "real.log"

    def test_no_roots_means_nothing_is_allowed(self):
        with pytest.raises(Refused, match="--allow-dir"):
            files.resolve("/var/log/x", [])

    def test_with_two_roots_either_works(self, logdir, tmp_path):
        other = tmp_path / "other"
        other.mkdir()
        (other / "o.log").write_text("x")
        roots = [logdir, other.resolve()]
        assert files.resolve(str(other / "o.log"), roots) == other.resolve() / "o.log"


class TestOpen:
    def test_a_regular_file_opens(self, logdir, roots):
        fd = files.open_checked(files.resolve(str(put(logdir, "a.log")), roots), roots)
        os.close(fd)

    def test_a_missing_file_says_so(self, logdir, roots):
        with pytest.raises(Refused, match="does not exist"):
            files.open_checked(logdir / "nope.log", roots)

    def test_a_directory_is_refused(self, logdir, roots):
        (logdir / "d").mkdir()
        with pytest.raises(Refused, match="not a regular file"):
            files.open_checked(logdir / "d", roots)

    def test_a_fifo_is_refused_without_blocking(self, logdir, roots):
        os.mkfifo(logdir / "pipe")
        with pytest.raises(Refused, match="not a regular file"):
            files.open_checked(logdir / "pipe", roots)

    def test_a_socket_file_is_refused(self, logdir, roots):
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(str(logdir / "sock"))
            with pytest.raises(Refused):
                files.open_checked(logdir / "sock", roots)
        finally:
            s.close()

    @pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="no /dev/zero")
    def test_a_device_is_refused_even_if_a_root_allows_dev(self):
        with pytest.raises(Refused, match="not a regular file"):
            files.open_checked(__import__("pathlib").Path("/dev/zero"), [__import__("pathlib").Path("/dev")])

    def test_a_final_symlink_is_not_followed_by_open(self, logdir, roots):
        # resolve() would already have replaced it; this is the second line of defence if it is swapped in later
        put(logdir, "real.log")
        os.symlink(logdir / "real.log", logdir / "swapped.log")
        with pytest.raises(Refused, match="cannot be opened"):
            files.open_checked(logdir / "swapped.log", roots)

    def test_the_file_that_is_really_open_must_be_inside(self, logdir, roots, tmp_path, monkeypatch):
        # a path that is checked as inside but whose open file turns out to be elsewhere (a swap in between)
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        real_open = os.open

        def swapped(path, flags, *a, **k):
            return real_open(outside, flags, *a, **k)

        put(logdir, "a.log")
        monkeypatch.setattr(files.os, "open", swapped)
        with pytest.raises(Refused, match="outside the allowed"):
            files.open_checked(logdir / "a.log", roots)

    def test_an_unreadable_file_says_so(self, logdir, roots):
        if os.geteuid() == 0:
            pytest.skip("root can read everything")
        p = put(logdir, "locked.log")
        p.chmod(0)
        with pytest.raises(Refused, match="cannot be read"):
            files.open_checked(p, roots)

    def test_the_descriptor_is_closed_when_a_check_fails(self, logdir, roots):
        (logdir / "d").mkdir()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(20):
            with pytest.raises(Refused):
                files.open_checked(logdir / "d", roots)
        assert len(os.listdir("/proc/self/fd")) == before

    def test_the_descriptor_is_not_inherited_by_children(self, logdir, roots):
        fd = files.open_checked(put(logdir, "a.log"), roots)
        try:
            assert not os.get_inheritable(fd)
        finally:
            os.close(fd)


class TestTail:
    def test_the_last_lines_in_order(self, logdir, roots):
        p = put(logdir, "a.log", "".join(f"line {i}\n" for i in range(1, 11)))
        lines, left_out, size = read(p, roots, lines=3)
        assert lines == ["line 8", "line 9", "line 10"]
        assert left_out is True
        assert size == p.stat().st_size

    def test_a_short_file_is_whole(self, logdir, roots):
        lines, left_out, _ = read(put(logdir, "a.log"), roots, lines=50)
        assert lines == ["line 1", "line 2", "line 3"]
        assert left_out is False

    def test_a_missing_final_newline_is_fine(self, logdir, roots):
        assert read(put(logdir, "a.log", "a\nb"), roots)[0] == ["a", "b"]

    def test_an_empty_file(self, logdir, roots):
        assert read(put(logdir, "a.log", ""), roots) == ([], False, 0)

    def test_contains_is_a_case_insensitive_plain_text_filter(self, logdir, roots):
        p = put(logdir, "a.log", "ok\nERROR disk full\nok\nerror again\nfine\n")
        assert read(p, roots, contains="Error")[0] == ["ERROR disk full", "error again"]

    def test_contains_is_not_a_pattern(self, logdir, roots):
        p = put(logdir, "a.log", "a.b\naxb\n(\n")
        assert read(p, roots, contains="a.b")[0] == ["a.b"]
        assert read(p, roots, contains="(")[0] == ["("]
        assert read(p, roots, contains=".*")[0] == []

    def test_only_the_last_megabyte_is_read_and_the_cut_line_is_dropped(self, logdir, roots):
        line = "x" * 99 + "\n"
        p = put(logdir, "big.log", line * 30000)  # 3 MB
        lines, left_out, size = read(p, roots, lines=500)
        assert size == 3_000_000
        assert left_out is True
        assert len(lines) == 500 and all(ln == "x" * 99 for ln in lines)

    def test_the_half_line_at_the_start_of_the_window_is_not_returned(self, logdir, roots):
        line = "x" * 99 + "\n"
        p = put(logdir, "big.log", line * 30000)  # the window starts in the middle of a line
        lines, left_out, _ = read(p, roots, lines=100_000)
        assert left_out is True
        assert 10_000 < len(lines) < 10_500
        assert set(lines) == {"x" * 99}

    def test_a_file_bigger_than_the_window_with_one_long_line_is_not_empty(self, logdir, roots):
        p = put(logdir, "one.log", "y" * (files.WINDOW + 5))
        lines, left_out, _ = read(p, roots)
        assert left_out is True
        assert len(lines) == 1

    def test_a_binary_file_is_refused(self, logdir, roots):
        (logdir / "bin").write_bytes(b"\x00\x01\x02 binary \xff\xfe")
        with pytest.raises(Refused, match="binary"):
            read(logdir / "bin", roots)

    def test_a_gzip_file_is_refused_as_binary(self, logdir, roots):
        import gzip

        (logdir / "old.log.gz").write_bytes(gzip.compress(b"hello\n" * 100))
        with pytest.raises(Refused, match="binary"):
            read(logdir / "old.log.gz", roots)

    def test_invalid_utf8_is_replaced_not_fatal(self, logdir, roots):
        (logdir / "latin.log").write_bytes(b"caf\xe9 ok\nsecond\n")
        assert read(logdir / "latin.log", roots)[0] == ["caf� ok", "second"]

    def test_unusual_line_separators_split_lines_and_cannot_hide_text(self, logdir, roots):
        (logdir / "u.log").write_bytes("a b\x0bc\x0cd\x85e\n".encode())
        assert read(logdir / "u.log", roots)[0] == ["a", "b", "c", "d", "e"]


class TestList:
    def test_files_two_levels_down_newest_first(self, logdir):
        a = put(logdir, "a.log")
        b = put(logdir, "sub/b.log")
        c = put(logdir, "sub/deeper/c.log")
        put(logdir, "sub/deeper/deepest/d.log")
        os.utime(c, (500_000, 500_000))
        os.utime(a, (1_000_000, 1_000_000))
        os.utime(b, (2_000_000, 2_000_000))
        found, more = files.list_logs([logdir], 100)
        paths = [f["path"] for f in found]
        assert paths[:2] == [str(b), str(a)]
        assert str(logdir / "sub" / "deeper" / "c.log") in paths
        assert not any("deepest" in p for p in paths)
        assert more is False
        assert found[0]["modified"] == "1970-01-24T03:33:20Z"

    def test_symlinks_are_skipped_not_followed(self, logdir, tmp_path):
        (tmp_path / "out").mkdir()
        (tmp_path / "out" / "x.log").write_text("x")
        os.symlink(tmp_path / "out", logdir / "dirlink")
        os.symlink(tmp_path / "out" / "x.log", logdir / "filelink")
        put(logdir, "real.log")
        assert [os.path.basename(f["path"]) for f in files.list_logs([logdir], 100)[0]] == ["real.log"]

    def test_pipes_and_sockets_are_not_listed(self, logdir):
        os.mkfifo(logdir / "pipe")
        put(logdir, "real.log")
        assert [os.path.basename(f["path"]) for f in files.list_logs([logdir], 100)[0]] == ["real.log"]

    def test_limit_and_truncation(self, logdir):
        for i in range(5):
            put(logdir, f"f{i}.log")
        found, more = files.list_logs([logdir], 3)
        assert len(found) == 3 and more is True

    def test_a_missing_directory_lists_nothing(self, tmp_path):
        assert files.list_logs([tmp_path / "nope"], 10) == ([], False)

    def test_readable_reflects_permissions(self, logdir):
        if os.geteuid() == 0:
            pytest.skip("root can read everything")
        p = put(logdir, "a.log")
        p.chmod(stat.S_IWUSR)
        assert files.list_logs([logdir], 10)[0][0]["readable"] is False
