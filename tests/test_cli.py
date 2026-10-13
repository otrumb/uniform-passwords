from __future__ import annotations

from dataclasses import dataclass, field
from io import StringIO

import pytest

from uniform_passwords.cli import CliStreams, parse_arguments, render_json, render_plain, run
from uniform_passwords.model import Batch, PasswordPolicy


@dataclass(slots=True)
class ConstantRank:
    rank: int
    calls: int = 0

    def __call__(self, upper_bound: int, /) -> int:
        assert 0 <= self.rank < upper_bound
        self.calls += 1
        return self.rank


@dataclass(slots=True)
class BrokenWriter:
    attempted: list[str] = field(default_factory=list)

    def write(self, text: str, /) -> int:
        self.attempted.append(text)
        raise BrokenPipeError


def test_plain_output_is_password_lines_only() -> None:
    batch = Batch(valid_space=123, entropy_bits=6.943, passwords=("alpha", "beta"))

    output = render_plain(batch)

    assert output == "alpha\nbeta\n"
    assert "entropy" not in output
    assert "123" not in output


def test_json_output_has_versioned_pretty_schema_and_rounded_entropy() -> None:
    policy = PasswordPolicy(length=4, symbols=False, exclude=("x", "y"))
    batch = Batch(valid_space=12345678901234567890, entropy_bits=63.420123, passwords=("aB3z",))

    output = render_json(policy, batch)
    assert (
        output
        == """{
  "schema_version": "uniform-passwords/v1",
  "policy": {
    "length": 4,
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": false,
    "ambiguous": true,
    "exclude": [
      "x",
      "y"
    ]
  },
  "valid_space": "12345678901234567890",
  "entropy_bits": 63.42,
  "passwords": [
    "aB3z"
  ]
}
"""
    )


@pytest.mark.parametrize("count", [0, 1001])
def test_count_outside_closed_range_is_usage_error(count: int) -> None:
    streams = CliStreams(stdout=StringIO(), stderr=StringIO())

    exit_code = run(("--count", str(count)), streams, ConstantRank(0))

    assert exit_code == 2


def test_output_size_above_limit_is_usage_error() -> None:
    streams = CliStreams(stdout=StringIO(), stderr=StringIO())

    exit_code = run(("--length", "1001", "--count", "1000"), streams, ConstantRank(0))

    assert exit_code == 2


def test_output_size_at_limit_is_accepted() -> None:
    stdout = StringIO()
    streams = CliStreams(stdout=stdout, stderr=StringIO())

    exit_code = run(("--length", "1000", "--count", "1000"), streams, ConstantRank(0))

    assert exit_code == 0
    assert len(stdout.getvalue().splitlines()) == 1000


def test_abbreviated_option_is_usage_error() -> None:
    streams = CliStreams(stdout=StringIO(), stderr=StringIO())

    exit_code = run(("--leng", "12"), streams, ConstantRank(0))

    assert exit_code == 2


@pytest.mark.parametrize(
    "option", ["--file", "--clipboard", "--network", "--telemetry", "--seed", "--unique"]
)
def test_forbidden_capability_is_not_a_cli_option(option: str) -> None:
    streams = CliStreams(stdout=StringIO(), stderr=StringIO())

    exit_code = run((option,), streams, ConstantRank(0))

    assert exit_code == 2


def test_json_flag_and_numeric_options_when_parsed() -> None:
    request = parse_arguments(("--length", "64", "--count", "7", "--json"))

    assert request.policy.length == 64
    assert request.count == 7
    assert request.json_output is True


def test_normal_operation_never_writes_passwords_to_stderr() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = run(("--count", "2"), CliStreams(stdout, stderr), ConstantRank(0))

    assert exit_code == 0
    assert len(stdout.getvalue().splitlines()) == 2
    assert stderr.getvalue() == ""


def test_broken_stdout_returns_one_without_copying_password_to_stderr() -> None:
    stdout = BrokenWriter()
    stderr = StringIO()

    exit_code = run((), CliStreams(stdout, stderr), ConstantRank(0))

    assert exit_code == 1
    assert stdout.attempted
    assert stdout.attempted[0].strip() not in stderr.getvalue()


def test_closed_stdout_returns_one_without_traceback() -> None:
    stdout = StringIO()
    stdout.close()
    stderr = StringIO()

    exit_code = run((), CliStreams(stdout, stderr), ConstantRank(0))

    assert exit_code == 1
    assert "unable to write output" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()
