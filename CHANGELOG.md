# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-10-21
- Initial public release
- CLI sniffer `extract_tibia.py` with Tibia framing, optional XTEA, opcode/byte extraction, JSON/CSV output
- Tkinter GUI `tibia_gui.py` with interface/port controls, Tibia frame, verbose toggle, XTEA scan/validate, log viewer
- GUI stats panel for live opcode counts; export JSON & clear session
- Auto-load opcode maps from `crystalserver` sources (client/server) or JSON cache files
- Verification scripts `verify_sniffer.py`, `test_callback.py`