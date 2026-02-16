"""Tests for query engine."""

import json
import os
import tempfile

import pytest

from ghidra_ai_bridge.config import Config
from ghidra_ai_bridge.query import normalize_address, find_function_file, load_json


def test_normalize_address():
    assert normalize_address("0x401000") == "00401000"
    assert normalize_address("401000") == "00401000"
    assert normalize_address("0x00401000") == "00401000"
    assert normalize_address("5fb010") == "005fb010"
    assert normalize_address("0") == "00000000"


def test_load_json_missing():
    result = load_json("/nonexistent/path.json")
    assert result == {}


def test_load_json_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"key": "value"}, f)
        f.flush()
        result = load_json(f.name)

    os.unlink(f.name)
    assert result == {"key": "value"}


def test_find_function_file_by_address():
    """Should find function file by direct address lookup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a mock function file
        func_data = {"address": "00401000", "name": "test_func", "decompiled": "void test() {}"}
        with open(os.path.join(tmpdir, "00401000.json"), "w") as f:
            json.dump(func_data, f)

        cfg = Config(export_dir=tmpdir, address_map_path=os.path.join(tmpdir, "nomap.json"))
        result = find_function_file("0x401000", cfg)
        assert result is not None
        assert "00401000.json" in result


def test_find_function_file_not_found():
    """Should return None for missing function."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(export_dir=tmpdir, address_map_path=os.path.join(tmpdir, "nomap.json"))
        result = find_function_file("0xDEADBEEF", cfg)
        assert result is None


def test_find_function_file_by_name():
    """Should find function by name via address map."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create address map
        address_map = {
            "00401000": {
                "name": "MyFunc",
                "class": "MyClass",
                "full_name": "MyClass::MyFunc",
                "file": "MyClass.cpp",
            }
        }
        map_path = os.path.join(tmpdir, "address_map.json")
        with open(map_path, "w") as f:
            json.dump(address_map, f)

        # Create function file
        func_data = {"address": "00401000", "name": "FUN_00401000", "decompiled": "void test() {}"}
        with open(os.path.join(tmpdir, "00401000.json"), "w") as f:
            json.dump(func_data, f)

        cfg = Config(export_dir=tmpdir, address_map_path=map_path)
        result = find_function_file("MyClass::MyFunc", cfg)
        assert result is not None
        assert "00401000.json" in result
