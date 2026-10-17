import pytest

from linux_diag_mcp import schema
from linux_diag_mcp.tools import REGISTRY, obj

S = obj(
    {
        "name": {"type": "string", "minLength": 2, "maxLength": 5, "pattern": r"[a-z]+"},
        "kind": {"type": "string", "enum": ["a", "b"]},
        "n": {"type": "integer", "minimum": 1, "maximum": 10},
        "flag": {"type": "boolean"},
    },
    required=("name",),
)


def errs(value):
    return schema.validate(value, S)


def test_a_good_value_has_no_errors():
    assert errs({"name": "abc", "kind": "a", "n": 3, "flag": False}) == []
    assert errs({"name": "ab"}) == []


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ([], "arguments must be an object"),
        ("x", "arguments must be an object"),
        (None, "arguments must be an object"),
        ({}, "name is required"),
        ({"name": "abc", "extra": 1}, "unknown argument 'extra'"),
        ({"name": 5}, "name must be a string"),
        ({"name": "a"}, "at least 2 characters"),
        ({"name": "abcdef"}, "at most 5 characters"),
        ({"name": "ABC"}, "not in an accepted form"),
        ({"name": "ab\n"}, "not in an accepted form"),
        ({"name": "ab", "kind": "c"}, "must be one of a, b"),
        ({"name": "ab", "n": "3"}, "n must be a whole number"),
        ({"name": "ab", "n": 3.0}, "n must be a whole number"),
        ({"name": "ab", "n": True}, "n must be a whole number"),
        ({"name": "ab", "n": 0}, "n must be at least 1"),
        ({"name": "ab", "n": 11}, "n must be at most 10"),
        ({"name": "ab", "n": 10**30}, "n must be at most 10"),
        ({"name": "ab", "flag": 1}, "flag must be true or false"),
        ({"name": "ab", "flag": "true"}, "flag must be true or false"),
    ],
)
def test_each_way_to_be_wrong_is_reported(value, message):
    assert any(message in e for e in errs(value)), errs(value)


def test_all_problems_are_listed_not_just_the_first():
    assert len(errs({"n": 0, "kind": "z", "bogus": 1})) == 4


def test_the_pattern_must_match_the_whole_string():
    # a "$" would let a trailing newline through; fullmatch does not
    assert errs({"name": "abc\n"})
    assert errs({"name": "abc def"})


def test_a_long_unknown_key_is_shortened_in_the_message():
    (msg,) = [e for e in errs({"name": "ab", "k" * 500: 1})]
    assert len(msg) < 200


class TestCheckSchema:
    def test_the_tools_own_schemas_pass(self):
        for t in REGISTRY.values():
            schema.check_schema(t.input_schema, t.name)

    @pytest.mark.parametrize(
        ("bad", "message"),
        [
            ({"type": "object", "properties": {}}, "additionalProperties"),
            (
                {"type": "object", "properties": {}, "additionalProperties": False, "oneOf": []},
                "unsupported keyword 'oneOf'",
            ),
            ({"type": "string", "format": "uri"}, "unsupported keyword 'format'"),
            ({"properties": {}}, "needs a type"),
            ({"type": "wat"}, "needs a type"),
            (
                {
                    "type": "object",
                    "properties": {"a": {"type": "string", "minItems": 1}},
                    "additionalProperties": False,
                },
                "unsupported keyword 'minItems'",
            ),
        ],
    )
    def test_anything_that_would_be_silently_ignored_is_refused(self, bad, message):
        with pytest.raises(ValueError, match=message):
            schema.check_schema(bad)


def test_every_tool_forbids_extra_arguments_and_bounds_its_numbers_and_strings():
    for t in REGISTRY.values():
        assert t.input_schema["additionalProperties"] is False, t.name
        for name, prop in t.input_schema["properties"].items():
            if prop["type"] == "integer":
                assert "minimum" in prop and "maximum" in prop, f"{t.name}.{name} has no bounds"
            if prop["type"] == "string":
                assert "maxLength" in prop or "enum" in prop, f"{t.name}.{name} has no length limit"
