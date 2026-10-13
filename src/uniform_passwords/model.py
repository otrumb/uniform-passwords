"""Immutable password policy and result values."""

from dataclasses import dataclass
from string import ascii_lowercase, ascii_uppercase, digits
from typing import Final

LOWERCASE: Final = ascii_lowercase
UPPERCASE: Final = ascii_uppercase
DIGITS: Final = digits
SYMBOLS: Final = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS: Final = "IlL1O0o|"
PRINTABLE_ASCII: Final = "".join(chr(code_point) for code_point in range(32, 127))
SCHEMA_VERSION: Final = "uniform-passwords/v1"


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Validated password composition policy."""

    length: int = 20
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    ambiguous: bool = True
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SamplingPolicy:
    """Concrete nonempty class alphabets used by exact sampler."""

    length: int
    classes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Request:
    """Validated CLI request."""

    policy: PasswordPolicy = PasswordPolicy()
    count: int = 1
    json_output: bool = False


@dataclass(frozen=True, slots=True)
class Batch:
    """Generated passwords and exact search-space metadata."""

    valid_space: int
    entropy_bits: float
    passwords: tuple[str, ...]
