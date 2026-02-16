"""Tests for address map builder."""

import json
import os
import tempfile

import pytest

from ghidra_ai_bridge.config import Config
from ghidra_ai_bridge.address_map import extract_addresses
from ghidra_ai_bridge.patterns.defaults import PRESETS


# Use plugin-sdk preset patterns for tests that need them
_PLUGIN_SDK = PRESETS["plugin-sdk"]


def _make_source(tmpdir: str, filename: str, content: str) -> None:
    filepath = os.path.join(tmpdir, filename)
    with open(filepath, "w") as f:
        f.write(content)


def test_extract_hook_patterns():
    """Should extract RH_ScopedInstall patterns when configured."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_source(tmpdir, "CMyClass.cpp", """
RH_ScopedClass(CMyClass);

void CMyClass::InjectHooks() {
    RH_ScopedInstall(DoThing, 0x401000);
    RH_ScopedInstall(DoOther, 0x401100);
}
""")

        cfg = Config(
            source_root=tmpdir,
            hook_patterns=_PLUGIN_SDK["hook_patterns"],
            class_macro=_PLUGIN_SDK["class_macro"],
        )
        result = extract_addresses(cfg)

        assert "00401000" in result
        assert result["00401000"]["name"] == "DoThing"
        assert result["00401000"]["class"] == "CMyClass"
        assert result["00401000"]["full_name"] == "CMyClass::DoThing"

        assert "00401100" in result
        assert result["00401100"]["name"] == "DoOther"


def test_extract_stub_patterns():
    """Should mark stub addresses when configured."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_source(tmpdir, "CStubClass.cpp", """
void CStubClass::Unfinished() {
    plugin::Call<0x402000>();
}
""")

        cfg = Config(
            source_root=tmpdir,
            stub_patterns=_PLUGIN_SDK["stub_patterns"],
        )
        result = extract_addresses(cfg)

        assert "00402000" in result
        assert result["00402000"]["stub"] is True


def test_class_macro_extraction():
    """Should prefer class macro for class name over filename."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_source(tmpdir, "SomeFile.cpp", """
RH_ScopedClass(CActualClass);

void CActualClass::InjectHooks() {
    RH_ScopedInstall(Method, 0x403000);
}
""")

        cfg = Config(
            source_root=tmpdir,
            hook_patterns=_PLUGIN_SDK["hook_patterns"],
            class_macro=_PLUGIN_SDK["class_macro"],
        )
        result = extract_addresses(cfg)

        assert result["00403000"]["class"] == "CActualClass"


def test_custom_patterns():
    """Should work with completely custom hook patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_source(tmpdir, "Custom.cpp", """
CUSTOM_HOOK(MyFunc, 0x500000);
""")

        cfg = Config(
            source_root=tmpdir,
            hook_patterns=[r'CUSTOM_HOOK\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)'],
            stub_patterns=[],
        )
        result = extract_addresses(cfg)

        assert "00500000" in result
        assert result["00500000"]["name"] == "MyFunc"


def test_empty_patterns():
    """With no patterns configured, should return empty map even with source files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_source(tmpdir, "Foo.cpp", """
RH_ScopedInstall(DoThing, 0x401000);
""")

        cfg = Config(source_root=tmpdir)  # Empty patterns by default
        result = extract_addresses(cfg)

        assert result == {}


def test_empty_source():
    """Should return empty map for non-existent source root."""
    cfg = Config(source_root="/nonexistent/path")
    result = extract_addresses(cfg)
    assert result == {}


def test_invalid_regex_no_traceback(capsys, tmp_path):
    """Invalid regex in config should print clean error, not traceback."""
    (tmp_path / "Foo.cpp").write_text("HOOK(Bar, 0x401000);\n")

    cfg = Config(
        source_root=str(tmp_path),
        hook_patterns=["(unclosed_group"],  # invalid regex
        stub_patterns=["[bad_bracket"],     # invalid regex
        class_macro="(also_broken",         # invalid regex
    )
    result = extract_addresses(cfg)

    # Should still return (empty map, since patterns didn't compile)
    assert isinstance(result, dict)

    # Should have printed clean error messages to stderr
    captured = capsys.readouterr()
    assert "Invalid hook_patterns pattern" in captured.err
    assert "Invalid stub_patterns pattern" in captured.err
    assert "Invalid class_macro pattern" in captured.err
