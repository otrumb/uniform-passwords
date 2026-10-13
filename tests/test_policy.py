from __future__ import annotations

import pytest

from uniform_passwords.cli import parse_arguments
from uniform_passwords.core import compile_policy, enabled_classes, validate_policy
from uniform_passwords.model import (
    AMBIGUOUS,
    DIGITS,
    LOWERCASE,
    PRINTABLE_ASCII,
    SYMBOLS,
    UPPERCASE,
    PasswordPolicy,
)


def test_defaults_when_no_arguments() -> None:
    request = parse_arguments(())

    assert request.policy == PasswordPolicy(
        length=20,
        lowercase=True,
        uppercase=True,
        digits=True,
        symbols=True,
        ambiguous=True,
        exclude=(),
    )
    assert request.count == 1
    assert request.json_output is False


def test_ascii_alphabets_are_fixed() -> None:
    assert LOWERCASE == "abcdefghijklmnopqrstuvwxyz"
    assert UPPERCASE == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert DIGITS == "0123456789"
    assert SYMBOLS == "!@#$%^&*()-_=+[]{};:,.?/"
    assert AMBIGUOUS == "IlL1O0o|"
    assert "".join(chr(code_point) for code_point in range(32, 127)) == PRINTABLE_ASCII


@pytest.mark.parametrize(
    ("arguments", "field", "enabled"),
    [
        (("--no-lowercase",), "lowercase", False),
        (("--lowercase",), "lowercase", True),
        (("--no-uppercase",), "uppercase", False),
        (("--uppercase",), "uppercase", True),
        (("--no-digits",), "digits", False),
        (("--digits",), "digits", True),
        (("--no-symbols",), "symbols", False),
        (("--symbols",), "symbols", True),
    ],
)
def test_boolean_option_when_explicit(
    arguments: tuple[str, ...], field: str, *, enabled: bool
) -> None:
    policy = parse_arguments(arguments).policy

    assert getattr(policy, field) is enabled


def test_repeatable_exclude_and_no_ambiguous_when_parsed() -> None:
    request = parse_arguments(("--exclude", "abc", "--exclude", "XYZ", "--no-ambiguous"))

    assert request.policy.exclude == ("abc", "XYZ")
    assert request.policy.ambiguous is False


def test_ambiguous_removal_is_intersection_only() -> None:
    classes = enabled_classes(PasswordPolicy(symbols=True, ambiguous=False))

    assert classes == (
        "abcdefghijkmnpqrstuvwxyz",
        "ABCDEFGHJKMNPQRSTUVWXYZ",
        "23456789",
        SYMBOLS.replace("|", ""),
    )


@pytest.mark.parametrize("length", [0, 1025])
def test_length_outside_closed_range_is_rejected(length: int) -> None:
    with pytest.raises(ValueError):
        _ = validate_policy(PasswordPolicy(length=length))


@pytest.mark.parametrize("excluded", ["line\nbreak", "café", "\x7f"])
def test_exclusion_outside_printable_ascii_is_rejected(excluded: str) -> None:
    with pytest.raises(ValueError):
        _ = validate_policy(PasswordPolicy(exclude=(excluded,)))


def test_no_enabled_classes_is_rejected() -> None:
    policy = PasswordPolicy(lowercase=False, uppercase=False, digits=False, symbols=False)

    with pytest.raises(ValueError):
        _ = validate_policy(policy)


def test_enabled_class_emptied_by_exclusions_is_rejected() -> None:
    policy = PasswordPolicy(
        uppercase=False,
        digits=False,
        symbols=False,
        exclude=(LOWERCASE,),
    )

    with pytest.raises(ValueError):
        _ = validate_policy(policy)


def test_length_smaller_than_nonempty_class_count_is_rejected() -> None:
    with pytest.raises(ValueError):
        _ = compile_policy(PasswordPolicy(length=3))


def test_empty_alphabet_after_cross_class_exclusions_is_rejected() -> None:
    policy = PasswordPolicy(exclude=(LOWERCASE + UPPERCASE + DIGITS + SYMBOLS,))

    with pytest.raises(ValueError):
        _ = compile_policy(policy)
