from __future__ import annotations

import runpy
import sys

import pytest


def test_package_module_exposes_cli_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["uniform_passwords", "--help"])

    with pytest.raises(SystemExit) as completion:
        _ = runpy.run_module("uniform_passwords", run_name="__main__")

    assert completion.value.code == 0
    assert "--length" in capsys.readouterr().out
