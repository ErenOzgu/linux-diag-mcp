"""Reading /proc and /sys directly. Every function takes the root to read from, so tests can point it at a
made-up tree and the real thing can be compared with ``free``, ``df``, ``ss`` and ``ps``."""

from __future__ import annotations

import ipaddress
import os
import pwd
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

PROC = Path("/proc")
SYS = Path("/sys")
TCP_LISTEN = "0A"
UDP_BOUND = "07"
PSEUDO_FS = {
    "proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "configfs",
    "fusectl", "pstore", "bpf", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "devtmpfs", "rpc_pipefs",
    "nsfs", "efivarfs", "selinuxfs", "squashfs", "ramfs",
}  # fmt: skip


class ProcError(Exception):
    """A file that should be there is missing or not in the expected shape."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ProcError(f"cannot read {path}: {exc.strerror}") from exc


def meminfo(root: Path = PROC) -> dict[str, int]:
    """/proc/meminfo with every value in bytes."""
    out: dict[str, int] = {}
    for line in _read(root / "meminfo").splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            out[name.strip()] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1)
    if "MemTotal" not in out:
        raise ProcError("/proc/meminfo has no MemTotal")
    return out


def uptime_seconds(root: Path = PROC) -> float:
    fields = _read(root / "uptime").split()
    try:
        return float(fields[0])
    except (IndexError, ValueError) as exc:
        raise ProcError("/proc/uptime is not in the expected shape") from exc


def loadavg(root: Path = PROC) -> tuple[float, float, float]:
    fields = _read(root / "loadavg").split()
    try:
        return float(fields[0]), float(fields[1]), float(fields[2])
    except (IndexError, ValueError) as exc:
        raise ProcError("/proc/loadavg is not in the expected shape") from exc


def cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def os_pretty_name(path: Path = Path("/etc/os-release")) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    return ""


def hostname() -> str:
    return socket.gethostname()


# ---- mounts and disks ----------------------------------------------------------------------------------


@dataclass
class Mount:
    device: str
    point: str
    fstype: str
    options: list[str]


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mounts(root: Path = PROC) -> list[Mount]:
    out = []
    for line in _read(root / "self" / "mounts").splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append(Mount(_unescape(f[0]), _unescape(f[1]), f[2], f[3].split(",")))
    return out


# ---- sockets -------------------------------------------------------------------------------------------


@dataclass
class Socket:
    protocol: str
    address: str
    port: int
    state: str
    inode: int


def _address(hexaddr: str, v6: bool) -> str:
    raw = bytes.fromhex(hexaddr)
    if not v6:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = struct.unpack("<4I", raw)  # four 32-bit words, each in host (little-endian) order
    return str(ipaddress.IPv6Address(struct.pack(">4I", *words)))


def sockets(protocol: str, root: Path = PROC) -> list[Socket]:
    """The sockets of one kind ("tcp", "tcp6", "udp", "udp6") as the kernel lists them."""
    v6 = protocol.endswith("6")
    out = []
    try:
        lines = _read(root / "net" / protocol).splitlines()[1:]
    except ProcError:
        return out  # for example IPv6 is switched off, so there is no tcp6 file
    for line in lines:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            addr_hex, port_hex = f[1].split(":")
            out.append(Socket(protocol, _address(addr_hex, v6), int(port_hex, 16), f[3], int(f[9])))
        except (ValueError, struct.error):
            continue
    return out


def socket_owners(root: Path = PROC) -> dict[int, tuple[int, str]]:
    """socket inode -> (pid, process name), for the processes whose file descriptors we may read."""
    owners: dict[int, tuple[int, str]] = {}
    try:
        entries = [e for e in os.listdir(root) if e.isdigit()]
    except OSError:
        return owners
    for pid in entries:
        fd_dir = root / pid / "fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        name = ""
        for fd in fds:
            try:
                target = os.readlink(fd_dir / fd)
            except OSError:
                continue
            if target.startswith("socket:["):
                if not name:
                    name = _comm(root, int(pid))
                owners.setdefault(int(target[8:-1]), (int(pid), name))
    return owners


# ---- processes -----------------------------------------------------------------------------------------


@dataclass
class Proc:
    pid: int
    name: str
    state: str
    ppid: int
    uid: int
    threads: int
    cpu_ticks: int
    start_ticks: int
    rss_bytes: int


def _comm(root: Path, pid: int) -> str:
    try:
        return (root / str(pid) / "comm").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _parse_stat(text: str) -> tuple[str, str, int, int, int, int, int]:
    """(name, state, ppid, cpu ticks, threads, start ticks, rss pages) from one /proc/PID/stat line.

    The name is in parentheses and may itself contain spaces and parentheses, so the fields after it are
    counted from the *last* closing parenthesis.
    """
    end = text.rfind(")")
    start = text.find("(")
    if start < 0 or end < start:
        raise ProcError("unexpected /proc/PID/stat")
    name = text[start + 1 : end]
    f = text[end + 2 :].split()
    # f[0] is field 3 (state); the proc(5) numbers below are f[n - 3]
    try:
        return name, f[0], int(f[1]), int(f[11]) + int(f[12]), int(f[17]), int(f[19]), int(f[21])
    except (IndexError, ValueError) as exc:
        raise ProcError("unexpected /proc/PID/stat") from exc


def processes(root: Path = PROC) -> list[Proc]:
    out = []
    page = os.sysconf("SC_PAGE_SIZE")
    try:
        entries = [e for e in os.listdir(root) if e.isdigit()]
    except OSError as exc:
        raise ProcError(f"cannot list {root}: {exc.strerror}") from exc
    for entry in entries:
        base = root / entry
        try:
            name, state, ppid, ticks, threads, started, rss = _parse_stat(
                (base / "stat").read_text(errors="replace")
            )
            uid = _real_uid(base)
        except (OSError, ProcError):
            continue  # it exited while we were reading, or we may not look
        out.append(Proc(int(entry), name, state, ppid, uid, threads, ticks, started, max(rss, 0) * page))
    return out


def _real_uid(base: Path) -> int:
    """Who the process belongs to: the real uid in ``status``. The owner of the /proc/PID directory is root for
    a process that is not dumpable (it dropped privileges, or is setuid), so it is only the fallback."""
    try:
        for line in (base / "status").read_text(errors="replace").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return os.stat(base).st_uid


def cmdline(pid: int, root: Path = PROC) -> str:
    try:
        raw = (root / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    return " ".join(raw.decode("utf-8", errors="replace").split("\0")).strip()


def user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def clock_ticks() -> int:
    return os.sysconf("SC_CLK_TCK")


# ---- network interfaces --------------------------------------------------------------------------------


def interfaces(sys_root: Path = SYS) -> list[dict]:
    base = sys_root / "class" / "net"
    out = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out

    def num(path: Path) -> int | None:
        try:
            return int(path.read_text().strip())
        except (OSError, ValueError):
            return None

    def text(path: Path) -> str:
        try:
            return path.read_text(errors="replace").strip()
        except OSError:
            return ""

    for name in names:
        d = base / name
        stats = d / "statistics"
        out.append(
            {
                "name": name,
                "state": text(d / "operstate"),
                "mtu": num(d / "mtu"),
                "mac": text(d / "address"),
                "rx_bytes": num(stats / "rx_bytes"),
                "tx_bytes": num(stats / "tx_bytes"),
                "rx_errors": num(stats / "rx_errors"),
                "tx_errors": num(stats / "tx_errors"),
                "rx_dropped": num(stats / "rx_dropped"),
                "tx_dropped": num(stats / "tx_dropped"),
            }
        )
    return out
