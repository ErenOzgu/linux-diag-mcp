"""Checking tool arguments against the small subset of JSON Schema the tools use.

Supported: ``type`` (object, string, integer, boolean), ``properties``, ``required``,
``additionalProperties: false``, ``enum``, ``minimum``, ``maximum``, ``minLength``, ``maxLength``, ``pattern``.
Anything else in a schema is a bug in this program and is refused when the tools are built.
"""

from __future__ import annotations

import re
from typing import Any

KEYWORDS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "description",
    "default",
    "title",
    "items",
    "examples",
}
TYPES = {"object", "string", "integer", "boolean", "array", "number", "null"}


def check_schema(schema: dict[str, Any], where: str = "schema") -> None:
    """Refuse a schema that uses something this module would silently ignore."""
    unknown = set(schema) - KEYWORDS
    if unknown:
        raise ValueError(f"{where}: unsupported keyword {sorted(unknown)[0]!r}")
    if schema.get("type") not in TYPES:
        raise ValueError(f"{where}: needs a type")
    if schema["type"] == "object" and schema.get("additionalProperties") is not False:
        raise ValueError(f"{where}: objects must set additionalProperties to false")
    for name, sub in schema.get("properties", {}).items():
        check_schema(sub, f"{where}.{name}")
    if "items" in schema:
        check_schema(schema["items"], f"{where}[]")


def validate(value: Any, schema: dict[str, Any], path: str = "arguments") -> list[str]:
    """Every way ``value`` does not fit ``schema``; an empty list means it fits."""
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict):
            return [f"{path} must be an object"]
        errors = []
        props = schema.get("properties", {})
        for key in value:
            if key not in props:
                allowed = ", ".join(props) or "none"
                errors.append(f"{path}: unknown argument {_show(key)} (this tool takes: {allowed})")
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: {key} is required")
        for key, sub in props.items():
            if key in value:
                errors += validate(value[key], sub, f"{path}.{key}" if path != "arguments" else key)
        return errors
    if kind == "string":
        if not isinstance(value, str):
            return [f"{path} must be a string"]
        errors = []
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path} must have at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path} must have at most {schema['maxLength']} characters")
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path} must be one of {', '.join(map(str, schema['enum']))}")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(
                f"{path} is not in an accepted form ({schema.get('description', 'see the tool description')})"
            )
        return errors
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return [f"{path} must be a whole number"]
        errors = []
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} must be at most {schema['maximum']}")
        return errors
    if kind == "boolean":
        return [] if isinstance(value, bool) else [f"{path} must be true or false"]
    raise ValueError(f"cannot validate type {kind!r}")


def _show(text: str) -> str:
    return repr(text if len(text) <= 40 else text[:39] + "…")
