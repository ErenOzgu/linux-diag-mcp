"""Cleaning what comes from the machine before a model reads it.

Two separate jobs. ``clean`` removes characters that can mislead a reader or a terminal (control codes,
ANSI escapes, bidirectional overrides). ``redact`` masks things that look like secrets. Neither can make text
safe to obey: a log line that says "ignore your instructions" is still that sentence after cleaning.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
# C0 controls except tab, DEL, C1 controls, bidirectional embeddings and isolates, zero-width and BOM characters
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]")

_SECRET_KEYS = (
    r"pass(?:word|wd|phrase)?|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
    r"auth(?:orization)?|credential[s]?|session[_\-]?id|cookie|client[_\-]?secret"
)
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL),
        "<private-key>",
    ),
    (re.compile(r"(\b[a-z][a-z0-9+.\-]*://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE), r"\1<credentials>@"),
    (
        re.compile(
            rf"(?<![A-Za-z0-9])((?:[A-Za-z0-9]+[_\-.])*(?:{_SECRET_KEYS})(?:[_\-.][A-Za-z0-9]+)*)"
            r"(\s*[\"']?\s*[=:]\s*[\"']?)(?:(?:bearer|basic)\s+)?(?!<)[^\s,;&\"']+",
            re.IGNORECASE,
        ),
        r"\1\2<secret>",
    ),
    (re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE), r"\1 <secret>"),
    (re.compile(r"\beyJ[\w\-]+\.[\w\-]+\.[\w\-]+\b"), "<jwt>"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<aws-key>"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"), "<github-token>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<slack-token>"),
    (re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{40,}\b"), "<token>"),
]


def clean(text: str, limit: int | None = None) -> str:
    """Drop escape sequences and control characters, make line breaks spaces, cut to ``limit`` characters."""
    text = _ANSI.sub("", text)
    text = text.replace("\r", " ").replace("\n", " ")  # a name or a command line is one line
    text = _CONTROL.sub("", text)
    if limit is not None and len(text) > limit:
        text = text[: max(limit - 1, 0)] + "…"
    return text


def redact(text: str) -> str:
    """Mask values that look like secrets. A list of patterns, not a guarantee."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


_BEGIN_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_END_KEY = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_BASE64_BODY = re.compile(r"[A-Za-z0-9+/=]{20,}")
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/=]{64,}")


def _private_key_lines(lines: list[str]) -> list[bool]:
    """Which lines are part of a PEM private key, including its body lines.

    A key block runs from its BEGIN line to its END line. A window that starts in the middle of one has an END
    with no BEGIN: the base64 lines just above it belong to the key too. A BEGIN that is never closed hides
    everything after it, which is the safe way to be wrong.
    """
    flags = [False] * len(lines)
    inside = False
    for i, line in enumerate(lines):
        if inside:
            flags[i] = True
            inside = not _END_KEY.search(line)
        elif _BEGIN_KEY.search(line):
            flags[i] = True
            inside = not _END_KEY.search(line)
        elif _END_KEY.search(line):
            flags[i] = True
            j = i - 1
            while j >= 0 and not flags[j] and _BASE64_BODY.fullmatch(lines[j].strip()):
                flags[j] = True
                j -= 1
    return flags


def sanitise_lines(raw: list[str], limit: int | None = None) -> tuple[list[str], int]:
    """``sanitise`` for a run of log lines, which also hides a private key that spans several of them.

    Returns the lines (a hidden key is one ``<private-key>`` line) and how many source lines were changed.
    """
    cleaned = [clean(line) for line in raw]
    flags = _private_key_lines(cleaned)
    out: list[str] = []
    changed = 0
    for line, in_key in zip(cleaned, flags, strict=True):
        if in_key:
            changed += 1
            if not out or out[-1] != "<private-key>":
                out.append("<private-key>")
            continue
        text = "<base64>" if _BASE64_LINE.fullmatch(line.strip()) else redact(line)
        changed += text != line
        out.append(text if limit is None or len(text) <= limit else text[: max(limit - 1, 0)] + "…")
    return out, changed


def sanitise(text: str, limit: int | None = None) -> tuple[str, bool]:
    """``clean`` then ``redact``, and whether redaction changed anything."""
    cleaned = clean(text)
    hidden = redact(cleaned)
    out = hidden if limit is None or len(hidden) <= limit else hidden[: max(limit - 1, 0)] + "…"
    return out, hidden != cleaned
