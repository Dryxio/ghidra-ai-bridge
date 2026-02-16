"""Build address-to-function-name map from reversed source code.

Walks source files looking for hook registration macros and stub patterns,
producing a JSON map of {address: {name, class, full_name, file}}.
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


def extract_addresses(cfg: Config) -> dict:
    """Extract function name -> address mappings from source."""
    address_map = {}

    source_root = cfg.source_root
    if not source_root or not os.path.isdir(source_root):
        print(f"ERROR: Source root not found: {source_root}")
        return address_map

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
            if cfg.class_macro:
                class_match = re.search(cfg.class_macro, content)
                if class_match:
                    class_name = class_match.group(1)

            # Extract hook registrations (name, address patterns)
            for pattern in cfg.hook_patterns:
                for match in re.finditer(pattern, content):
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
            for pattern in cfg.stub_patterns:
                for match in re.finditer(pattern, content):
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

    return address_map


def build_address_map(cfg: Config) -> int:
    """Build address map and save to configured path. Returns exit code."""
    print(f"Scanning {cfg.source_root}...")
    address_map = extract_addresses(cfg)

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
    return 0
