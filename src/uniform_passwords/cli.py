"""uniform-passwords command-line boundary."""

import argparse
import json
import secrets
import sys
from collections.abc import Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from typing import NoReturn, Protocol, final, override

from uniform_passwords.core import PolicyError, RandBelow, compile_policy, generate
from uniform_passwords.model import SCHEMA_VERSION, Batch, PasswordPolicy, Request


class TextWriter(Protocol):
    """Writable text stream capability."""

    def write(self, text: str, /) -> int:
        """Write text and return consumed character count."""
        ...


@dataclass(slots=True)
class _RedirectWriter:
    target: TextWriter

    def write(self, text: str, /) -> int:
        return self.target.write(text)

    def flush(self) -> None:
        return None


@dataclass(slots=True)
class _FlushingWriter:
    target: TextWriter

    def write(self, text: str, /) -> int:
        consumed = self.target.write(text)
        _ = sys.stdout.flush()
        return consumed


@dataclass(frozen=True, slots=True)
class CliStreams:
    """CLI output streams."""

    stdout: TextWriter
    stderr: TextWriter


@dataclass(frozen=True, slots=True)
class ParserExitError(Exception):
    """Argparse completion represented without terminating process."""

    status: int
    message: str | None


@final
class ArgumentParser(argparse.ArgumentParser):
    """Argument parser whose exits remain inside ``run``."""

    @override
    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ParserExitError(status=status, message=message)


@final
class ParsedArguments(argparse.Namespace):
    """Typed mutable namespace populated by argparse."""

    length: int
    count: int
    lowercase: bool
    uppercase: bool
    digits: bool
    symbols: bool
    ambiguous: bool
    excluded_values: list[str]
    json_output: bool

    def __init__(self) -> None:
        """Initialize defaults before argparse mutates namespace."""
        super().__init__()
        self.length = 20
        self.count = 1
        self.lowercase = True
        self.uppercase = True
        self.digits = True
        self.symbols = True
        self.ambiguous = True
        self.excluded_values = []
        self.json_output = False


def _parser() -> ArgumentParser:
    parser = ArgumentParser(prog="uniform-passwords", allow_abbrev=False)
    _ = parser.add_argument("--length", type=int, default=20)
    _ = parser.add_argument("--count", type=int, default=1)
    _ = parser.add_argument("--lowercase", action=argparse.BooleanOptionalAction, default=True)
    _ = parser.add_argument("--uppercase", action=argparse.BooleanOptionalAction, default=True)
    _ = parser.add_argument("--digits", action=argparse.BooleanOptionalAction, default=True)
    _ = parser.add_argument("--symbols", action=argparse.BooleanOptionalAction, default=True)
    _ = parser.add_argument("--ambiguous", action=argparse.BooleanOptionalAction, default=True)
    _ = parser.add_argument("--exclude", action="append", default=[], dest="excluded_values")
    _ = parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def parse_arguments(arguments: Sequence[str]) -> Request:
    """Parse CLI arguments without abbreviation."""
    parsed = _parser().parse_args(arguments, namespace=ParsedArguments())
    return Request(
        policy=PasswordPolicy(
            length=parsed.length,
            lowercase=parsed.lowercase,
            uppercase=parsed.uppercase,
            digits=parsed.digits,
            symbols=parsed.symbols,
            ambiguous=parsed.ambiguous,
            exclude=tuple(parsed.excluded_values),
        ),
        count=parsed.count,
        json_output=parsed.json_output,
    )


def render_plain(batch: Batch) -> str:
    """Render one password per line without metadata."""
    return "".join(f"{password}\n" for password in batch.passwords)


def render_json(policy: PasswordPolicy, batch: Batch) -> str:
    """Render one pretty UTF-8 JSON document."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "policy": {
            "length": policy.length,
            "lowercase": policy.lowercase,
            "uppercase": policy.uppercase,
            "digits": policy.digits,
            "symbols": policy.symbols,
            "ambiguous": policy.ambiguous,
            "exclude": policy.exclude,
        },
        "valid_space": str(batch.valid_space),
        "entropy_bits": round(batch.entropy_bits, 2),
        "passwords": batch.passwords,
    }
    return f"{json.dumps(document, indent=2)}\n"


def run(arguments: Sequence[str], streams: CliStreams, randbelow: RandBelow) -> int:
    """Run CLI with injected streams and rank source."""
    try:
        with (
            redirect_stdout(_RedirectWriter(streams.stdout)),
            redirect_stderr(_RedirectWriter(streams.stderr)),
        ):
            request = parse_arguments(arguments)
    except ParserExitError as error:
        if error.message:
            _ = streams.stderr.write(error.message)
        return error.status

    try:
        policy = compile_policy(request.policy)
        batch = generate(policy, request.count, randbelow)
    except PolicyError as error:
        _ = streams.stderr.write(f"error: {error}\n")
        return 2

    output = render_json(request.policy, batch) if request.json_output else render_plain(batch)
    try:
        _ = streams.stdout.write(output)
    except (OSError, ValueError) as error:
        _ = streams.stderr.write(f"error: unable to write output: {error}\n")
        return 1
    return 0


def main() -> int:
    """Run installed command."""
    streams = CliStreams(stdout=_FlushingWriter(sys.stdout), stderr=sys.stderr)
    exit_code = run(sys.argv[1:], streams, secrets.randbelow)
    if exit_code == 1:
        sys.stdout = None
    return exit_code
