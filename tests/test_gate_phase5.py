"""Phase 5 gate checks: vendored patterns in the secret scan, the narrow allowlist with its
stale-entry check (D20), vendor integrity against the manifest (D19, D29), and the validator
coverage floor. Secret-shaped strings are built at runtime from parts (D30)."""

from __future__ import annotations

import hashlib
import importlib
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest

AWS_KEY = "AK" + "IA" + "A" * 16
IN_SCOPE = "src/ai_security_assistant/third_party/secret_scanner/core/x.py"
HEX64 = "a" * 64


def vendored_fake(gate: ModuleType, rule_id: str) -> str:
    """A fake secret built at runtime by the vendored builder (D30)."""
    gate.vendored_engine()
    fakes = importlib.import_module(f"{gate._VENDOR_ALIAS}.core.fakes")
    rules = importlib.import_module(f"{gate._VENDOR_ALIAS}.core.rules")
    document = json.loads((gate.VENDOR_DIR / "rules" / "builtin.json").read_text(encoding="utf-8"))
    rule = next(r for r in rules.parse_rules_document(document) if r.id == rule_id)
    fake: str = fakes.build_fake(rule, seed="gate-test")
    return fake


# ---------------------------------------------------------------- vendored patterns


def test_vendored_patterns_extend_the_scan(gate: ModuleType) -> None:
    fake = vendored_fake(gate, "gitlab-pat")
    assert gate.scan_text(f"x = {fake}") == []  # the gate's own patterns miss it
    assert gate.vendored_hits(f"line one\nx = {fake}\n".encode()) == [(2, "vendored:gitlab-pat")]
    problems = gate.scan_files([("a.py", f"x = {fake}".encode())], [])
    assert problems == ["a.py:1: vendored:gitlab-pat"]
    assert all(fake not in p for p in problems)


def test_vendored_scan_has_entropy_off(gate: ModuleType) -> None:
    digest = hashlib.sha256(b"x").hexdigest()
    assert gate.vendored_hits(f"digest = {digest}".encode()) == []


def test_binary_files_are_skipped(gate: ModuleType) -> None:
    assert gate.scan_files([("a.bin", f"\0{AWS_KEY}".encode())], []) == []


def test_the_vendored_package_loads_once_under_a_private_name(gate: ModuleType) -> None:
    first = gate._load_vendored_package()
    assert gate._load_vendored_package() is first
    assert first.__name__ == gate._VENDOR_ALIAS


# ---------------------------------------------------------------- allowlist (D20)


def test_an_allowlist_entry_suppresses_exactly_its_line(gate: ModuleType) -> None:
    lines = [f"a = {AWS_KEY}", f"b = {AWS_KEY}"]
    entry = (IN_SCOPE, gate.line_sha256(lines[0]))
    problems = gate.scan_files([(IN_SCOPE, "\n".join(lines).encode())], [entry])
    assert problems and all(p.startswith(f"{IN_SCOPE}:2:") for p in problems)


def test_an_allowlist_entry_only_applies_to_its_own_path(gate: ModuleType) -> None:
    line = f"a = {AWS_KEY}"
    other = IN_SCOPE.replace("x.py", "y.py")
    problems = gate.scan_files([(other, line.encode())], [(IN_SCOPE, gate.line_sha256(line))])
    assert any(p.startswith(f"{other}:1:") for p in problems)
    assert any(p.startswith("stale scan allowlist entry") for p in problems)


def test_a_stale_allowlist_entry_is_an_error(gate: ModuleType) -> None:
    entry = (IN_SCOPE, gate.line_sha256("a line that matches nothing"))
    problems = gate.scan_files([(IN_SCOPE, b"a line that matches nothing\n")], [entry])
    assert problems == [f"stale scan allowlist entry: {IN_SCOPE} {entry[1][:12]}..."]


def test_an_edited_allowed_line_invalidates_its_entry(gate: ModuleType) -> None:
    entry = (IN_SCOPE, gate.line_sha256(f"a = {AWS_KEY}"))
    problems = gate.scan_files([(IN_SCOPE, f"a  = {AWS_KEY}".encode())], [entry])
    assert any(p.startswith(f"{IN_SCOPE}:1:") for p in problems)
    assert any(p.startswith("stale") for p in problems)


def test_crlf_and_lf_give_the_same_line_hash(gate: ModuleType) -> None:
    line = f"a = {AWS_KEY}"
    entry = (IN_SCOPE, gate.line_sha256(line))
    assert gate.line_sha256(line) == gate.line_sha256(line + "\n")
    crlf = f"first\r\n{line}\r\nlast\r\n".encode()
    assert gate.scan_files([(IN_SCOPE, crlf)], [entry]) == []


def _entry(path: str = IN_SCOPE, sha: str = HEX64, reason: str = "r") -> str:
    return f'[[entry]]\npath = "{path}"\nsha256 = "{sha}"\nreason = "{reason}"\n'


@pytest.mark.parametrize(
    ("toml", "needle"),
    [
        ("entry = [", "invalid TOML"),
        ("other = 1", "only [[entry]]"),
        ("entry = 3", "array of tables"),
        ('[[entry]]\npath = "x"\nsha256 = "y"\n', "exactly path, sha256 and reason"),
        (_entry(reason=" "), "non-empty"),
        (_entry(sha="A" * 64), "64 lower-case"),
        (_entry(path="tests/test_x.py"), "scopes"),
        (_entry(path="tests/fixtures/secret_scanner/../../x.py"), "scopes"),
        (_entry() * 2, "duplicate"),
    ],
)
def test_a_malformed_allowlist_is_refused(gate: ModuleType, toml: str, needle: str) -> None:
    _entries, problems = gate.load_allowlist(toml)
    assert any(needle in p for p in problems), problems


def test_an_empty_allowlist_is_valid(gate: ModuleType) -> None:
    assert gate.load_allowlist("# nothing allowed\n") == ([], [])


def test_the_real_allowlist_is_narrow_and_valid(gate: ModuleType) -> None:
    entries, problems = gate.load_allowlist(gate.SCAN_ALLOWLIST.read_text(encoding="utf-8"))
    assert problems == []
    assert 1 <= len(entries) <= 5
    assert all(path.startswith(gate.ALLOWLIST_SCOPES) for path, _ in entries)


def test_the_secret_scan_reports_allowlist_problems(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bad = tmp_path / "allow.toml"
    bad.write_text("other = 1\n", encoding="utf-8")
    monkeypatch.setattr(gate, "SCAN_ALLOWLIST", bad)
    assert gate.check_secret_scan() == ["scan allowlist: only [[entry]] tables are allowed"]


# ---------------------------------------------------------------- vendor integrity (D19, D29)


@pytest.fixture
def vendor_copy(gate: ModuleType, tmp_path: Path) -> Path:
    target = tmp_path / "secret_scanner"
    shutil.copytree(gate.VENDOR_DIR, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def test_the_real_vendored_tree_matches_its_manifest(gate: ModuleType) -> None:
    assert gate.check_vendor_integrity() == []
    assert gate.check_vendor_integrity in [check for _name, check in gate.CHECKS]


def test_a_changed_byte_fails_the_manifest(gate: ModuleType, vendor_copy: Path) -> None:
    path = vendor_copy / "core" / "rules.py"
    data = bytearray(path.read_bytes())
    data[100] ^= 0x01
    path.write_bytes(bytes(data))
    assert gate.vendor_problems(vendor_copy) == [
        "vendored file does not match the manifest: core/rules.py"
    ]


def test_crlf_checkout_still_matches_the_manifest(gate: ModuleType, vendor_copy: Path) -> None:
    for path in vendor_copy.rglob("*"):
        if path.is_file():
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert gate.vendor_problems(vendor_copy) == []


def test_unlisted_and_missing_files_fail(gate: ModuleType, vendor_copy: Path) -> None:
    (vendor_copy / "core" / "extra.py").write_text("x = 1\n", encoding="utf-8")
    (vendor_copy / "core" / "lines.py").unlink()
    (vendor_copy / "__pycache__").mkdir()
    (vendor_copy / "__pycache__" / "x.pyc").write_bytes(b"\0")
    assert gate.vendor_problems(vendor_copy) == [
        "vendored file not in the manifest: core/extra.py",
        "manifest lists a missing file: core/lines.py",
    ]


def test_a_wrong_version_fails(gate: ModuleType, vendor_copy: Path) -> None:
    assert gate.vendor_problems(vendor_copy, "v1.0.1") == ["VERSION does not say version: v1.0.1"]


def test_a_missing_manifest_fails_loudly(gate: ModuleType, vendor_copy: Path) -> None:
    (vendor_copy / gate.MANIFEST_NAME).unlink()
    with pytest.raises(FileNotFoundError):
        gate.vendor_problems(vendor_copy)


@pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("not a manifest line", "malformed line"),
        (f"{HEX64}  ../outside.py", "path must be relative"),
        (f"{HEX64}  /abs.py", "path must be relative"),
        (f"{HEX64}  LICENSE", "duplicate path"),
    ],
)
def test_a_malformed_manifest_fails(
    gate: ModuleType, vendor_copy: Path, line: str, needle: str
) -> None:
    manifest = vendor_copy / gate.MANIFEST_NAME
    manifest.write_bytes(manifest.read_bytes() + line.encode() + b"\n")
    assert any(needle in p for p in gate.vendor_problems(vendor_copy))


def test_version_must_be_in_the_manifest(gate: ModuleType, vendor_copy: Path) -> None:
    manifest = vendor_copy / gate.MANIFEST_NAME
    lines = manifest.read_text(encoding="utf-8").split("\n")
    manifest.write_text("\n".join(ln for ln in lines if not ln.endswith("VERSION")), "utf-8")
    problems = gate.vendor_problems(vendor_copy)
    assert "VERSION is not in the manifest" in problems
    assert "vendored file not in the manifest: VERSION" in problems


def test_the_ast_ban_scans_the_vendored_code(gate: ModuleType) -> None:
    vendored = sorted(gate.VENDOR_DIR.rglob("*.py"))
    assert vendored and all(gate.SRC in path.parents for path in vendored)
    assert gate.check_ast_ban() == []


# ---------------------------------------------------------------- coverage floor


def test_tests_include_the_validator_coverage_floor(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str]) -> list[str]:
        calls.append(list(args))
        return []

    monkeypatch.setattr(gate, "run_tool", fake_run)
    assert gate.check_tests() == []
    assert "--cov-fail-under=90" in calls[0]
    assert calls[1][-2:] == ["--include=*/ai_security_assistant/validator/*", "--fail-under=95"]
