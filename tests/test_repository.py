from __future__ import annotations

from importlib.metadata import requires
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]
ALLOWED_FILES = {
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".gitignore",
    ".python-version",
    "CHANGELOG.md",
    "LICENSE",
    "PROVENANCE.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
    "src/uniform_passwords/__init__.py",
    "src/uniform_passwords/__main__.py",
    "src/uniform_passwords/cli.py",
    "src/uniform_passwords/core.py",
    "src/uniform_passwords/model.py",
    "tests/test_cli.py",
    "tests/test_module.py",
    "tests/test_policy.py",
    "tests/test_repository.py",
    "tests/test_sampler.py",
}
IGNORED_PARTS = {".git", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "build", "dist"}


def test_runtime_dependencies_are_empty() -> None:
    assert requires("uniform-passwords") is None


def test_repository_contains_only_allowlisted_files() -> None:
    files = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in PROJECT_ROOT.rglob("*")
        if path.is_file() and not IGNORED_PARTS.intersection(path.parts)
    }

    assert files == ALLOWED_FILES


def test_repository_has_no_private_artifacts() -> None:
    forbidden_names = {".env", "id_rsa", "id_ed25519", "credentials.json", "secrets.json"}
    forbidden_suffixes = {".key", ".pem", ".pfx", ".p12"}
    files = [path for path in PROJECT_ROOT.rglob("*") if path.is_file()]

    assert not [
        path
        for path in files
        if path.name.lower() in forbidden_names or path.suffix.lower() in forbidden_suffixes
    ]


def test_repository_text_has_no_private_paths_or_secret_markers() -> None:
    private_markers = (
        "-----BEGIN " + "PRIVATE KEY-----",
        "C:" + "\\Users\\",
        "C:/" + "Users/",
        "/" + "home/",
        "/" + "Users/",
    )
    findings: dict[str, list[str]] = {}
    for relative_path in ALLOWED_FILES:
        path = PROJECT_ROOT / relative_path
        text = path.read_text(encoding="utf-8")
        matches = [marker for marker in private_markers if marker in text]
        if matches:
            findings[relative_path] = matches

    assert findings == {}


def test_python_modules_stay_within_250_pure_lines() -> None:
    oversized: dict[str, int] = {}
    for path in PROJECT_ROOT.rglob("*.py"):
        if IGNORED_PARTS.intersection(path.parts):
            continue
        source = path.read_text(encoding="utf-8")
        pure_lines = sum(
            bool(line.strip()) and not line.lstrip().startswith("#") for line in source.splitlines()
        )
        if pure_lines > 250:
            oversized[path.relative_to(PROJECT_ROOT).as_posix()] = pure_lines

    assert oversized == {}
