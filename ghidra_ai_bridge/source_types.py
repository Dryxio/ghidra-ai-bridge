"""Export struct layouts and enum definitions from reversed source code.

Extracts type information from VALIDATE_SIZE / VALIDATE_OFFSET macros
and enum definitions in header files.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


def extract_validate_size(content: str, filepath: Path, source_root: Path) -> dict:
    """Extract struct sizes from size validation macros."""
    pattern = r'VALIDATE_SIZE\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
    results = {}
    for match in re.finditer(pattern, content):
        name = match.group(1)
        size_str = match.group(2)
        size = int(size_str, 16) if size_str.startswith('0x') else int(size_str)
        try:
            rel = str(filepath.relative_to(source_root))
        except ValueError:
            rel = str(filepath)
        results[name] = {
            "name": name,
            "size_hex": hex(size),
            "size_dec": size,
            "file": rel,
        }
    return results


def extract_validate_offset(content: str, validate_offset_macro: str) -> dict:
    """Extract field offsets from offset validation macros."""
    results = defaultdict(list)
    for match in re.finditer(validate_offset_macro, content):
        struct_name = match.group(1)
        field_name = match.group(2)
        offset_str = match.group(3)
        offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
        results[struct_name].append({
            "field": field_name,
            "offset_hex": hex(offset),
            "offset_dec": offset,
        })
    return results


def extract_enums(content: str, filepath: Path, source_root: Path) -> dict:
    """Extract enum definitions from source."""
    enums = {}

    pattern = r'enum\s+(\w+)\s*(?::\s*\w+)?\s*\{([^}]+)\}'

    for match in re.finditer(pattern, content, re.DOTALL):
        enum_name = match.group(1)
        enum_body = match.group(2)

        values = []
        current_value = 0

        for line in enum_body.split('\n'):
            line = re.sub(r'//.*$', '', line).strip()
            line = line.rstrip(',').strip()

            if not line or line.startswith('/*'):
                continue

            if '=' in line:
                parts = line.split('=', 1)
                name = parts[0].strip()
                value_str = parts[1].strip()

                try:
                    if value_str.startswith('0x'):
                        current_value = int(value_str, 16)
                    elif '<<' in value_str:
                        m = re.match(r'(\d+)\s*<<\s*(\d+)', value_str)
                        if m:
                            current_value = int(m.group(1)) << int(m.group(2))
                        else:
                            current_value = 0
                    elif value_str.lstrip('-').isdigit():
                        current_value = int(value_str)
                    else:
                        continue
                except (ValueError, OverflowError):
                    continue
            else:
                name = line

            if name and re.match(r'^[A-Za-z_]\w*$', name):
                values.append({
                    "name": name,
                    "value": current_value,
                    "value_hex": hex(current_value) if current_value >= 0 else str(current_value),
                })
                current_value += 1

        if values:
            try:
                rel = str(filepath.relative_to(source_root))
            except ValueError:
                rel = str(filepath)
            enums[enum_name] = {
                "name": enum_name,
                "file": rel,
                "values": values,
            }

    return enums


def find_stubs(cfg: Config) -> list[dict]:
    """Find all remaining stub function calls in source."""
    source_root = Path(cfg.source_root)
    stubs = []
    seen_files: set[Path] = set()

    for ext in cfg.file_extensions:
        for src_file in source_root.rglob(f"*{ext}"):
            if src_file in seen_files:
                continue
            seen_files.add(src_file)
            try:
                content = src_file.read_text(errors='ignore')

                for stub_pattern in cfg.stub_patterns:
                    for match in re.finditer(stub_pattern + r'[^;]*;', content):
                        start = max(0, match.start() - 500)
                        context = content[start:match.start()]

                        func_match = re.search(
                            r'(\w+::\w+)\s*\([^)]*\)\s*(?:const\s*)?\{[^}]*$',
                            context, re.DOTALL,
                        )
                        func_name = func_match.group(1) if func_match else "unknown"

                        addr_match = re.search(r'(0x[0-9A-Fa-f]+)', match.group(0))
                        addr = addr_match.group(1) if addr_match else "unknown"

                        try:
                            rel = str(src_file.relative_to(source_root))
                        except ValueError:
                            rel = str(src_file)

                        stubs.append({
                            "function": func_name,
                            "address": addr,
                            "file": rel,
                            "stub": match.group(0)[:100],
                        })
            except Exception:
                pass

    return stubs


def export_source_types(cfg: Config) -> int:
    """Export all source type information. Returns exit code."""
    source_root = Path(cfg.source_root)
    if not source_root.is_dir():
        print(f"ERROR: Source root not found: {source_root}")
        return 1

    print("=" * 60)
    print("Exporting Source Type Information")
    print("=" * 60)

    os.makedirs(cfg.export_dir, exist_ok=True)

    all_structs = {}
    all_offsets = defaultdict(list)
    all_enums = {}

    print("\nScanning source files...")
    header_count = 0

    for ext in cfg.file_extensions:
        for header in source_root.rglob(f"*{ext}"):
            try:
                content = header.read_text(errors='ignore')
                header_count += 1

                structs = extract_validate_size(content, header, source_root)
                all_structs.update(structs)

                offsets = extract_validate_offset(content, cfg.validate_offset_macro)
                for struct_name, fields in offsets.items():
                    all_offsets[struct_name].extend(fields)

                enums = extract_enums(content, header, source_root)
                all_enums.update(enums)
            except Exception:
                pass

    # Merge offsets into structs
    for struct_name, fields in all_offsets.items():
        if struct_name in all_structs:
            all_structs[struct_name]["fields"] = sorted(fields, key=lambda x: x["offset_dec"])

    print(f"  Scanned {header_count} headers")
    print(f"  Found {len(all_structs)} structs with sizes")
    print(f"  Found {len(all_enums)} enum definitions")

    # Find remaining stubs
    print("\nFinding remaining stubs...")
    stubs = find_stubs(cfg)
    print(f"  Found {len(stubs)} remaining stubs")

    stubs_by_class = defaultdict(list)
    for stub in stubs:
        class_name = stub["function"].split("::")[0] if "::" in stub["function"] else "Other"
        stubs_by_class[class_name].append(stub)

    # Save outputs
    print("\nSaving outputs...")

    structs_path = os.path.join(cfg.export_dir, "_source_structs.json")
    with open(structs_path, "w") as f:
        json.dump(all_structs, f, indent=2)
    print(f"  {structs_path}")

    enums_path = os.path.join(cfg.export_dir, "_source_enums.json")
    with open(enums_path, "w") as f:
        json.dump(all_enums, f, indent=2)
    print(f"  {enums_path}")

    stubs_path = os.path.join(cfg.export_dir, "_remaining_stubs.json")
    with open(stubs_path, "w") as f:
        json.dump({
            "total": len(stubs),
            "by_class": {k: len(v) for k, v in sorted(stubs_by_class.items(), key=lambda x: -len(x[1]))},
            "stubs": stubs,
        }, f, indent=2)
    print(f"  {stubs_path}")

    print(f"\nStructs with sizes:  {len(all_structs)}")
    print(f"Enums with values:   {len(all_enums)}")
    print(f"Remaining stubs:     {len(stubs)}")

    return 0
