"""Build address-to-function-name map from reversed source code.

Walks source files looking for hook registration macros and stub patterns,
producing a JSON map of {address: {name, class, full_name, file}}.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


def _compile_patterns(patterns: list[str], label: str) -> tuple[list[re.Pattern], int]:
    """Compile regex patterns, printing a clear error for invalid ones.

    Returns ``(compiled_list, failure_count)``.
    """
    compiled = []
    failures = 0
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as exc:
            failures += 1
            print(f"ERROR: Invalid {label} pattern: {p!r}", file=sys.stderr)
            print(f"       {exc}", file=sys.stderr)
    return compiled, failures


def extract_addresses(cfg: Config) -> tuple[dict, bool]:
    """Extract function name -> address mappings from source.

    Returns ``(address_map, had_pattern_errors)`` where *had_pattern_errors*
    is ``True`` when at least one configured pattern failed to compile.
    """
    address_map: dict = {}

    source_root = cfg.source_root
    if not source_root or not os.path.isdir(source_root):
        print(f"ERROR: Source root not found: {source_root}")
        return address_map, False

    hook_re, hook_fail = _compile_patterns(cfg.hook_patterns, "hook_patterns")
    stub_re, stub_fail = _compile_patterns(cfg.stub_patterns, "stub_patterns")

    class_fail = 0
    class_re = None
    if cfg.class_macro:
        try:
            class_re = re.compile(cfg.class_macro)
        except re.error as exc:
            class_fail = 1
            print(f"ERROR: Invalid class_macro pattern: {cfg.class_macro!r}", file=sys.stderr)
            print(f"       {exc}", file=sys.stderr)

    had_errors = (hook_fail + stub_fail + class_fail) > 0

    for root, dirs, files in os.walk(source_root):
        for filename in files:
            if not any(filename.endswith(ext) for ext in cfg.file_extensions):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, source_root)

            # Default class name from filename (strip any extension)
            base = filename
            for ext in cfg.file_extensions:
                if base.endswith(ext):
                    base = base[:-len(ext)]
                    break
            class_name = base

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Find class name from class macro
            if class_re:
                class_match = class_re.search(content)
                if class_match:
                    class_name = class_match.group(1)

            # Extract hook registrations (name, address patterns)
            for pat in hook_re:
                for match in pat.finditer(content):
                    func_name = match.group(1)
                    address = match.group(2).lower()

                    addr_int = int(address, 16)
                    addr_norm = f"{addr_int:08x}"

                    if func_name != "nullptr":
                        address_map[addr_norm] = {
                            "name": func_name,
                            "class": class_name,
                            "full_name": f"{class_name}::{func_name}",
                            "file": rel_path,
                        }

            # Extract stub addresses (unreversed functions)
            for pat in stub_re:
                for match in pat.finditer(content):
                    address = match.group(1).lower()
                    addr_int = int(address, 16)
                    addr_norm = f"{addr_int:08x}"

                    if addr_norm not in address_map:
                        address_map[addr_norm] = {
                            "name": "UNREVERSED",
                            "class": class_name,
                            "full_name": f"{class_name}::UNREVERSED",
                            "file": rel_path,
                            "stub": True,
                        }

    return address_map, had_errors


def build_address_map(cfg: Config) -> int:
    """Build address map and save to configured path. Returns exit code."""
    print(f"Scanning {cfg.source_root}...")
    address_map, had_pattern_errors = extract_addresses(cfg)

    print(f"Found {len(address_map)} function addresses")

    reversed_count = sum(1 for v in address_map.values() if not v.get('stub'))
    stub_count = sum(1 for v in address_map.values() if v.get('stub'))

    print(f"  - Reversed: {reversed_count}")
    print(f"  - Stubs: {stub_count}")

    # Ensure output directory exists
    os.makedirs(os.path.dirname(cfg.address_map_path), exist_ok=True)

    with open(cfg.address_map_path, 'w') as f:
        json.dump(address_map, f, indent=2)

    print(f"Saved to {cfg.address_map_path}")

    if had_pattern_errors:
        print("WARNING: Some patterns failed to compile (see errors above).",
              file=sys.stderr)
        return 1

    return 0
