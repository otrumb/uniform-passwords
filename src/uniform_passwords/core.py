"""Exact uniform constrained password sampling."""

from dataclasses import dataclass
from functools import lru_cache
from math import log2
from typing import Final, Protocol, override

from uniform_passwords.model import (
    AMBIGUOUS,
    DIGITS,
    LOWERCASE,
    PRINTABLE_ASCII,
    SYMBOLS,
    UPPERCASE,
    Batch,
    PasswordPolicy,
    SamplingPolicy,
)

MAX_LENGTH: Final = 1024
MAX_COUNT: Final = 1000
MAX_OUTPUT_SIZE: Final = 1_000_000


class RandBelow(Protocol):
    """Narrow cryptographic rank source."""

    def __call__(self, upper_bound: int, /) -> int:
        """Return an integer in ``range(upper_bound)``."""
        ...


@dataclass(frozen=True, slots=True)
class PolicyError(ValueError):
    """Invalid password-generation policy."""

    reason: str

    @override
    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class RankError(ValueError):
    """Rank outside exact valid password space."""

    rank: int
    valid_space: int

    @override
    def __str__(self) -> str:
        return f"rank {self.rank} is outside [0, {self.valid_space})"


def validate_policy(policy: PasswordPolicy) -> PasswordPolicy:
    """Validate and normalize a policy at the application boundary."""
    if not 1 <= policy.length <= MAX_LENGTH:
        raise PolicyError(reason=f"length must be between 1 and {MAX_LENGTH}")
    if not any((policy.lowercase, policy.uppercase, policy.digits, policy.symbols)):
        raise PolicyError(reason="at least one character class must be enabled")
    if any(character not in PRINTABLE_ASCII for value in policy.exclude for character in value):
        raise PolicyError(reason="excluded characters must be printable ASCII")
    classes = enabled_classes(policy)
    if any(not alphabet for alphabet in classes):
        raise PolicyError(reason="exclusions must not empty an enabled character class")
    return policy


def enabled_classes(policy: PasswordPolicy) -> tuple[str, ...]:
    """Resolve enabled alphabets after ambiguity and exclusion intersection removal."""
    excluded = frozenset("".join(policy.exclude))
    if not policy.ambiguous:
        excluded |= frozenset(AMBIGUOUS)
    configured: tuple[tuple[bool, str], ...] = (
        (policy.lowercase, LOWERCASE),
        (policy.uppercase, UPPERCASE),
        (policy.digits, DIGITS),
        (policy.symbols, SYMBOLS),
    )
    return tuple(
        "".join(character for character in alphabet if character not in excluded)
        for enabled, alphabet in configured
        if enabled
    )


def compile_policy(policy: PasswordPolicy) -> SamplingPolicy:
    """Convert validated CLI policy to concrete sampling policy."""
    validated = validate_policy(policy)
    classes = enabled_classes(validated)
    if validated.length < len(classes):
        raise PolicyError(reason="length must cover every enabled character class")
    return SamplingPolicy(length=validated.length, classes=classes)


@lru_cache(maxsize=128)
def _suffix_counts(policy: SamplingPolicy) -> tuple[tuple[int, ...], ...]:
    class_count = len(policy.classes)
    full_mask = (1 << class_count) - 1
    rows: list[tuple[int, ...]] = [
        tuple(1 if mask == full_mask else 0 for mask in range(full_mask + 1))
    ]
    for _remaining in range(policy.length):
        previous = rows[-1]
        rows.append(
            tuple(
                sum(
                    len(alphabet) * previous[mask | (1 << class_index)]
                    for class_index, alphabet in enumerate(policy.classes)
                )
                for mask in range(full_mask + 1)
            )
        )
    return tuple(rows)


def count_valid(policy: SamplingPolicy) -> int:
    """Count valid strings exactly with bitmask dynamic programming."""
    return _suffix_counts(policy)[policy.length][0]


def unrank(policy: SamplingPolicy, rank: int) -> str:
    """Map a valid-space rank to one valid password bijectively."""
    counts = _suffix_counts(policy)
    valid_space = counts[policy.length][0]
    if not 0 <= rank < valid_space:
        raise RankError(rank=rank, valid_space=valid_space)

    mask = 0
    password: list[str] = []
    for remaining in range(policy.length, 0, -1):
        for class_index, alphabet in enumerate(policy.classes):
            next_mask = mask | (1 << class_index)
            suffix_count = counts[remaining - 1][next_mask]
            block_size = len(alphabet) * suffix_count
            if rank >= block_size:
                rank -= block_size
                continue
            character_index, rank = divmod(rank, suffix_count)
            password.append(alphabet[character_index])
            mask = next_mask
            break
    return "".join(password)


def generate(policy: SamplingPolicy, count: int, randbelow: RandBelow) -> Batch:
    """Draw one rank per password and unrank each independently."""
    if not 1 <= count <= MAX_COUNT:
        raise PolicyError(reason=f"count must be between 1 and {MAX_COUNT}")
    if policy.length * count > MAX_OUTPUT_SIZE:
        raise PolicyError(reason=f"length times count must not exceed {MAX_OUTPUT_SIZE}")
    valid_space = count_valid(policy)
    passwords = tuple(unrank(policy, randbelow(valid_space)) for _index in range(count))
    return Batch(
        valid_space=valid_space,
        entropy_bits=log2(valid_space),
        passwords=passwords,
    )
