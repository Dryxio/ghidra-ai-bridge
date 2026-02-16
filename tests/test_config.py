"""Tests for config loading."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from ghidra_ai_bridge.config import Config, load_config, _find_config_file


def test_default_config():
    """Config with no sources should have sensible defaults."""
    cfg = load_config(config_path="/nonexistent/path.yaml")
    assert cfg.export_dir == os.path.expanduser("~/.ghidra-exports")
    assert cfg.address_map_path.endswith("address_map.json")
    # Patterns are empty by default (project-specific, not hardcoded)
    assert cfg.hook_patterns == []
    assert cfg.stub_patterns == []
    # File extensions have generic defaults
    assert len(cfg.file_extensions) > 0


def test_yaml_loading():
    """Config should load from YAML file."""
    data = {
        "ghidra": {
            "install_dir": "/opt/ghidra",
            "project_dir": "/tmp/ghidra-project",
            "project_name": "test-project",
            "program_name": "test.exe",
        },
        "paths": {
            "export_dir": "/tmp/exports",
            "address_map": "/tmp/exports/map.json",
        },
        "binary": {
            "code_range_min": "0x00401000",
            "code_range_max": "0x00900000",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        cfg = load_config(config_path=f.name)

    os.unlink(f.name)

    assert cfg.ghidra_install_dir == "/opt/ghidra"
    assert cfg.ghidra_project_dir == "/tmp/ghidra-project"
    assert cfg.ghidra_project_name == "test-project"
    assert cfg.ghidra_program_name == "test.exe"
    assert cfg.export_dir == "/tmp/exports"
    assert cfg.code_range_min == 0x00401000
    assert cfg.code_range_max == 0x00900000


def test_env_override(monkeypatch):
    """Environment variables should override YAML."""
    data = {
        "ghidra": {"install_dir": "/from/yaml"},
        "paths": {"export_dir": "/from/yaml/exports"},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/from/env")
        monkeypatch.setenv("GHIDRA_EXPORT_DIR", "/from/env/exports")
        cfg = load_config(config_path=f.name)

    os.unlink(f.name)

    assert cfg.ghidra_install_dir == "/from/env"
    assert cfg.export_dir == "/from/env/exports"


def test_cli_override():
    """CLI overrides should take highest priority."""
    data = {
        "paths": {"export_dir": "/from/yaml"},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        cfg = load_config(
            config_path=f.name,
            cli_overrides={"export_dir": "/from/cli"},
        )

    os.unlink(f.name)

    assert cfg.export_dir == "/from/cli"


def test_derived_paths():
    """Derived path properties should be based on export_dir."""
    cfg = Config(export_dir="/tmp/exports")
    assert cfg.index_file == "/tmp/exports/_index.json"
    assert cfg.structs_file == "/tmp/exports/_structs.json"
    assert cfg.enums_file == "/tmp/exports/_enums.json"


def test_has_source_false():
    """has_source should be False when no source root configured."""
    cfg = Config()
    assert not cfg.has_source


def test_has_code_range():
    """has_code_range should reflect whether both bounds are set."""
    cfg = Config()
    assert not cfg.has_code_range

    cfg.code_range_min = 0x401000
    cfg.code_range_max = 0x900000
    assert cfg.has_code_range


def test_source_config():
    """Source-related settings should load from YAML."""
    data = {
        "source": {
            "root": "/tmp/src",
            "hook_patterns": [r"MY_HOOK\((\w+),\s*(0x[0-9A-Fa-f]+)\)"],
            "stub_patterns": [r"MY_STUB\((0x[0-9A-Fa-f]+)\)"],
            "class_macro": r"MY_CLASS\((\w+)\)",
            "stub_markers": ["TODO_REVERSE"],
            "file_extensions": [".c", ".h"],
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        cfg = load_config(config_path=f.name)

    os.unlink(f.name)

    assert cfg.source_root == "/tmp/src"
    assert len(cfg.hook_patterns) == 1
    assert "MY_HOOK" in cfg.hook_patterns[0]
    assert cfg.stub_markers == ["TODO_REVERSE"]
    assert ".c" in cfg.file_extensions
