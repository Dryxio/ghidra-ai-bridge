"""Interactive setup wizard for ghidra-bridge init."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from ghidra_ai_bridge.patterns.defaults import PRESETS


def _prompt(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    result = input(f"{msg}{suffix}: ").strip()
    return result or default


def _prompt_bool(msg: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    result = input(f"{msg}{suffix}: ").strip().lower()
    if not result:
        return default
    return result in ("y", "yes")


def run_wizard() -> int:
    """Run interactive setup wizard. Returns exit code."""
    print("=" * 50)
    print("  ghidra-ai-bridge setup wizard")
    print("=" * 50)
    print()

    config: dict = {}

    # --- Ghidra settings ---
    print("--- Ghidra Project Settings ---")
    ghidra_install = _prompt("Ghidra install directory")
    if ghidra_install:
        expanded = os.path.expanduser(ghidra_install)
        if not os.path.isdir(expanded):
            print(f"  Warning: Directory not found: {expanded}")

    ghidra_project_dir = _prompt("Ghidra project directory")
    ghidra_project_name = _prompt("Ghidra project name")
    ghidra_program_name = _prompt("Program name (binary in project)")

    config["ghidra"] = {
        "install_dir": ghidra_install,
        "project_dir": ghidra_project_dir,
        "project_name": ghidra_project_name,
        "program_name": ghidra_program_name,
    }

    # --- Paths ---
    print("\n--- Export Paths ---")
    export_dir = _prompt("Export directory for JSON data", ".ghidra-exports")
    address_map = os.path.join(export_dir, "address_map.json")

    config["paths"] = {
        "export_dir": export_dir,
        "address_map": address_map,
    }

    # --- Source integration (optional) ---
    print("\n--- Source Code Integration (optional) ---")
    print("  If you have reversed/reimplemented source code with hook macros,")
    print("  ghidra-bridge can build an address map and track progress.")
    has_source = _prompt_bool("Do you have reversed source code to integrate?", default=False)

    if has_source:
        source_root = _prompt("Source root directory")
        config["source"] = {
            "root": source_root,
        }

        # Offer presets
        if PRESETS:
            print("\n  Available pattern presets:")
            preset_names = list(PRESETS.keys())
            for i, name in enumerate(preset_names, 1):
                desc = PRESETS[name].get("description", name)
                print(f"    {i}. {name} — {desc}")
            print(f"    {len(preset_names) + 1}. custom (define your own patterns)")

            choice = _prompt("Select preset number, or press Enter to skip")
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(preset_names):
                    preset = PRESETS[preset_names[idx]]
                    config["source"]["hook_patterns"] = preset.get("hook_patterns", [])
                    config["source"]["stub_patterns"] = preset.get("stub_patterns", [])
                    if preset.get("class_macro"):
                        config["source"]["class_macro"] = preset["class_macro"]
                    if preset.get("stub_markers"):
                        config["source"]["stub_markers"] = preset["stub_markers"]
                    print(f"  Applied preset: {preset_names[idx]}")
                else:
                    print("  No preset applied. Edit patterns in ghidra-bridge.yaml manually.")
            else:
                print("  No preset applied. Edit patterns in ghidra-bridge.yaml manually.")

    # --- Binary range (optional) ---
    print("\n--- Binary Code Range (optional) ---")
    has_range = _prompt_bool("Configure code range filter for containing-address lookups?", default=False)
    if has_range:
        code_min = _prompt("Code range minimum (hex)", "0x00401000")
        code_max = _prompt("Code range maximum (hex)", "0x00900000")
        config["binary"] = {
            "code_range_min": code_min,
            "code_range_max": code_max,
        }

    # --- Write file ---
    output_path = Path("ghidra-bridge.yaml")
    print(f"\n--- Writing {output_path} ---")

    with open(output_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Config written to: {output_path.resolve()}")
    print()
    print("Next steps:")
    print(f"  1. Run exports:   ghidra-bridge export all")
    if has_source:
        print(f"  2. Build map:     ghidra-bridge build-map")
    print(f"  3. Query:         ghidra-bridge decompile <address>")
    print(f"  4. Check stats:   ghidra-bridge info")

    return 0
