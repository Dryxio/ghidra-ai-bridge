"""Allow running as `python -m ghidra_ai_bridge`."""

from ghidra_ai_bridge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
