"""Running the few external programs the tools use. An argument list, never a shell."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

# Output we are willing to hold in memory from one command.
MAX_BYTES = 1_000_000
# A fixed, small environment: no user PATH tricks, no locale surprises, no pager, no colour.
ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "SYSTEMD_PAGER": "",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_URLIFY": "0",
}


class NotInstalled(Exception):
    """The program is not on this machine."""


class RunFailed(Exception):
    """The program timed out or could not be started."""


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False


class Runner:
    """Runs allowlisted commands. Tests replace this with a fake that records what was asked."""

    def run(self, argv: list[str], timeout: float = 10.0) -> Result:
        try:
            p = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                env=ENV,
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise NotInstalled(argv[0]) from exc
        except subprocess.TimeoutExpired as exc:
            raise RunFailed(f"{argv[0]} took longer than {timeout:g} s") from exc
        except OSError as exc:
            raise RunFailed(f"{argv[0]} could not be started: {exc.strerror}") from exc
        out = p.stdout[:MAX_BYTES]
        return Result(
            p.returncode,
            out.decode("utf-8", errors="replace"),
            p.stderr[:20_000].decode("utf-8", errors="replace"),
            len(p.stdout) > MAX_BYTES,
        )
