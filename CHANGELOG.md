# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2025-10-21
- CLI profiles for `login`/`game`, automatic Tibia frame activation, and guidance when XTEA is missing
- Auto XTEA extraction helper for Linux (CLI + GUI), with GUI status logging and key auto-fill
- Platform-specific capture hints (Linux setcap guidance, Windows Npcap requirement)
- Mark `python-ptrace` as Linux-only in requirements

## [0.1.1] - 2025-10-21
- Add GitHub Actions release workflow to build CLI and GUI binaries on tag push
- Add VERSION and update README with release and usage docs
- GUI: mapping status label, Export JSON and Clear session buttons, structured events storage

## [0.1.0] - 2025-10-21
- Initial public release
- CLI sniffer `extract_tibia.py` with Tibia framing, optional XTEA, opcode/byte extraction, JSON/CSV output
- Tkinter GUI `tibia_gui.py` with interface/port controls, Tibia frame, verbose toggle, XTEA scan/validate, log viewer
- GUI stats panel for live opcode counts; export JSON & clear session
- Auto-load opcode maps from `crystalserver` sources (client/server) or JSON cache files
- Verification scripts `verify_sniffer.py`, `test_callback.py`