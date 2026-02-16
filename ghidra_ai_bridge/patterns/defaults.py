"""Default regex patterns for source code integration.

These are generic defaults. Project-specific patterns (hook macros, stub
markers, class macros) should be defined in your ghidra-bridge.yaml config.

The source integration features (build-map, remaining, source-struct, etc.)
are entirely optional — ghidra-ai-bridge works fine with just Ghidra exports.
"""

# Hook registration patterns: each must capture (function_name, address).
# Empty by default — configure in ghidra-bridge.yaml for your project's macros.
HOOK_PATTERNS: list[str] = []

# Stub patterns: each must capture (address) for unreversed function calls.
# Empty by default — configure in ghidra-bridge.yaml.
STUB_PATTERNS: list[str] = []

# Class extraction macro: must capture (class_name). Empty = use filename.
CLASS_MACRO = ""

# Struct size validation macro: must capture (struct_name, size).
VALIDATE_SIZE_MACRO = r'VALIDATE_SIZE\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'

# Field offset validation macro: must capture (struct_name, field_name, offset).
VALIDATE_OFFSET_MACRO = r'VALIDATE_OFFSET\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'

# Markers indicating unreversed code. Empty by default.
STUB_MARKERS: list[str] = []

# Source file extensions to scan.
FILE_EXTENSIONS = ['.cpp', '.h', '.hpp']


# ---------------------------------------------------------------------------
# Preset pattern sets for known RE frameworks
# ---------------------------------------------------------------------------

PRESETS: dict[str, dict] = {
    "plugin-sdk": {
        "description": "plugin-sdk / ReversibleHooks framework",
        "hook_patterns": [
            r'RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)',
            r'RH_ScopedVMTInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)',
        ],
        "stub_patterns": [
            r'plugin::Call\w*<[^>]*(0x[0-9A-Fa-f]+)[^>]*>',
        ],
        "class_macro": r'RH_ScopedClass\s*\(\s*(\w+)\s*\)',
        "stub_markers": ["NOTSA_UNREACHABLE"],
    },
}
