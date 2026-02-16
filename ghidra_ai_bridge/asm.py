"""ASM dump wrapper — extract instruction-level assembly from a Ghidra project.

Requires pyghidra and a configured Ghidra project.
"""

from __future__ import annotations

import os
import string
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra_ai_bridge.config import Config


def _looks_like_hex_address(target: str) -> bool:
    t = target.lower()
    if t.startswith("0x"):
        t = t[2:]
    return bool(t) and all(ch in string.hexdigits for ch in t)


def _resolve_function(program, fm, target: str):
    """Resolve a function by address or exact name."""
    if _looks_like_hex_address(target):
        value = int(target, 16)
        space = program.getAddressFactory().getDefaultAddressSpace()
        addr = space.getAddress(value)
        fn = fm.getFunctionAt(addr)
        if fn is not None:
            return fn

    it = fm.getFunctions(True)
    while it.hasNext():
        fn = it.next()
        if fn.getName() == target:
            return fn
    return None


def dump_asm(
    target: str,
    output: str,
    *,
    refs_out: str | None = None,
    cfg: Config | None = None,
) -> int:
    """Dump assembly for a function to a file. Returns exit code."""
    try:
        import pyghidra
    except ImportError:
        print("ERROR: pyghidra is required for dump-asm. Install with: pip install ghidra-ai-bridge[headless]")
        return 1

    ghidra_install = cfg.ghidra_install_dir if cfg else ""
    project_location = cfg.ghidra_project_dir if cfg else ""
    project_name = cfg.ghidra_project_name if cfg else ""
    program_name = cfg.ghidra_program_name if cfg else ""

    if ghidra_install:
        os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_install)

    if not project_location or not project_name:
        print("ERROR: Ghidra project location and name must be configured.")
        return 1

    with pyghidra.open_program(
        None,
        project_location=project_location,
        project_name=project_name,
        program_name=program_name,
        analyze=False,
        nested_project_location=False,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()
        symtab = program.getSymbolTable()

        fn = _resolve_function(program, fm, target)
        if fn is None:
            print(f"ERROR: Function not found for target '{target}'", file=sys.stderr)
            return 1

        asm_lines = [f"{inst.getAddress()} {inst}" for inst in listing.getInstructions(fn.getBody(), True)]
        Path(output).write_text("\n".join(asm_lines) + "\n", encoding="utf-8")

        print(f"Wrote ASM: {output} ({len(asm_lines)} instructions)")
        print(f"Function: {fn.getName()} @ {fn.getEntryPoint()}")

        if refs_out:
            refs = {}
            for inst in listing.getInstructions(fn.getBody(), True):
                for ref in inst.getReferencesFrom():
                    to = ref.getToAddress()
                    if to is None:
                        continue
                    offset = to.getOffset()
                    if offset not in refs:
                        sym = symtab.getPrimarySymbol(to)
                        refs[offset] = (to, sym.getName() if sym else "unknown", str(ref.getReferenceType()))

            ref_lines = []
            for _, (addr, name, rtype) in sorted(refs.items(), key=lambda x: x[0]):
                ref_lines.append(f"0x{addr.getOffset():08x} {name} [{rtype}]")

            Path(refs_out).write_text("\n".join(ref_lines) + ("\n" if ref_lines else ""), encoding="utf-8")
            print(f"Wrote refs: {refs_out} ({len(ref_lines)} unique refs)")

    return 0
