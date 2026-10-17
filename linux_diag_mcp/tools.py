"""What a tool is, and the registry the tools add themselves to."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import procfs, schema
from .runner import Runner


class ToolError(Exception):
    """A tool cannot do what was asked. The message goes to the model, so it says what to change."""


@dataclass
class Context:
    """Everything a tool may touch. Tests build one with a fake runner and a made-up /proc."""

    runner: Runner = field(default_factory=Runner)
    allow_dirs: list[Path] = field(default_factory=list)
    proc: Path = procfs.PROC
    sys: Path = procfs.SYS
    users: Callable[[int], str] = procfs.user_name
    sleep: Callable[[float], None] = time.sleep
    now: Callable[[], float] = time.time
    monotonic: Callable[[], float] = time.monotonic


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler: Callable[[Context, dict[str, Any]], dict[str, Any]]

    def definition(self) -> dict[str, Any]:
        """The entry for ``tools/list``. Every tool is read-only and touches only this machine."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }


REGISTRY: dict[str, Tool] = {}


def obj(properties: dict[str, Any] | None = None, required: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "properties": properties or {}, "additionalProperties": False}
    if required:
        out["required"] = list(required)
    return out


def tool(
    name: str,
    title: str,
    description: str,
    properties: dict[str, Any] | None = None,
    required: tuple[str, ...] = (),
    output: dict[str, Any] | None = None,
) -> Callable[
    [Callable[[Context, dict[str, Any]], dict[str, Any]]], Callable[[Context, dict[str, Any]], dict[str, Any]]
]:
    """Register a handler as a tool. The input schema is checked here, so a typo fails at import."""
    input_schema = obj(properties, required)
    schema.check_schema(input_schema, name)

    def register(fn):  # noqa: ANN001, ANN202
        if name in REGISTRY:
            raise ValueError(f"tool {name} is registered twice")
        REGISTRY[name] = Tool(name, title, description, input_schema, output or {"type": "object"}, fn)
        return fn

    return register
