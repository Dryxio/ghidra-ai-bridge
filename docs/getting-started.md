# Getting Started with ghidra-ai-bridge

## Prerequisites

- Python 3.10+
- A Ghidra project with your target binary analyzed
- (Optional) [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) for headless exports

## Step 1: Install

```bash
pip install ghidra-ai-bridge

# With headless export support:
pip install ghidra-ai-bridge[headless]
```

## Step 2: Configure

Run the interactive wizard:

```bash
cd /path/to/your/project
ghidra-bridge init
```

This creates a `ghidra-bridge.yaml` in the current directory.

Or create it manually — see the [example config](../examples/gta-sa/ghidra-bridge.yaml).

## Step 3: Export Ghidra Data

```bash
# Export everything (requires pyghidra)
ghidra-bridge export all

# Or export specific types
ghidra-bridge export structs
ghidra-bridge export decompiled
```

This populates your export directory with JSON files that the query engine reads.

## Step 4: Build Address Map (Optional)

If you have reversed source code with hook macros:

```bash
ghidra-bridge build-map
```

This scans your source for hook registrations and builds a mapping from addresses to function names.

## Step 5: Query

```bash
# Decompile a function
ghidra-bridge decompile 0x401000

# Search by name
ghidra-bridge search MyClass

# Show cross-references
ghidra-bridge xrefs-to 0x5fb010
ghidra-bridge xrefs-from 0x5fb010

# Inspect types
ghidra-bridge struct CEntity
ghidra-bridge enum eWeaponType
ghidra-bridge vtable CVehicle

# Find crash location
ghidra-bridge containing 0x5fb123

# Check progress
ghidra-bridge info
ghidra-bridge remaining MyClass
```

## Integrating with AI Agents

The CLI is designed for AI agents. Point your agent's tool configuration at `ghidra-bridge`:

```bash
# In your agent's tool definition
ghidra-bridge --config /path/to/ghidra-bridge.yaml decompile 0x401000
```

All commands produce clean, parseable text output suitable for LLM consumption.

## Custom Hook Patterns

If your project uses different macros for hook registration, configure custom patterns in YAML:

```yaml
source:
  root: ./source
  hook_patterns:
    - 'MY_HOOK_MACRO\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)'
  stub_patterns:
    - 'CALL_ORIGINAL\s*\(\s*(0x[0-9A-Fa-f]+)'
  class_macro: 'MY_CLASS_MACRO\s*\(\s*(\w+)\s*\)'
```

Each hook pattern must have two capture groups: `(function_name, address)`.
Each stub pattern must have one capture group: `(address)`.
