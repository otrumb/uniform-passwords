from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from uniform_passwords.core import count_valid, generate, unrank
from uniform_passwords.model import SamplingPolicy


@dataclass(slots=True)
class FakeRandBelow:
    ranks: list[int]
    calls: list[int] = field(default_factory=list)

    def __call__(self, upper_bound: int, /) -> int:
        self.calls.append(upper_bound)
        return self.ranks.pop(0)


def test_exact_count_when_two_classes_and_length_two() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))

    assert count_valid(policy) == 8


def test_unrank_boundaries_when_tiny_policy() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))

    first = unrank(policy, 0)
    last = unrank(policy, 7)

    assert first in {"a1", "a2", "b1", "b2", "1a", "1b", "2a", "2b"}
    assert last in {"a1", "a2", "b1", "b2", "1a", "1b", "2a", "2b"}
    assert first != last


def test_unrank_is_exhaustive_bijection_when_tiny_policy() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))

    passwords = {unrank(policy, rank) for rank in range(count_valid(policy))}

    assert passwords == {"a1", "a2", "b1", "b2", "1a", "1b", "2a", "2b"}


@pytest.mark.parametrize("rank", [-1, 8])
def test_unrank_outside_valid_space_is_rejected(rank: int) -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))

    with pytest.raises(ValueError):
        _ = unrank(policy, rank)


def test_generate_draws_exactly_once_per_password() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))
    randbelow = FakeRandBelow([0, 3, 7])

    batch = generate(policy, 3, randbelow)

    assert randbelow.calls == [8, 8, 8]
    assert batch.passwords == (unrank(policy, 0), unrank(policy, 3), unrank(policy, 7))


def test_repeated_ranks_allow_duplicate_passwords() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))
    randbelow = FakeRandBelow([2, 2])

    batch = generate(policy, 2, randbelow)

    assert batch.passwords == (unrank(policy, 2), unrank(policy, 2))
    assert randbelow.calls == [8, 8]


def test_entropy_is_log2_of_exact_valid_space() -> None:
    policy = SamplingPolicy(length=2, classes=("ab", "12"))

    batch = generate(policy, 1, FakeRandBelow([0]))

    assert batch.valid_space == 8
    assert batch.entropy_bits == 3.0
