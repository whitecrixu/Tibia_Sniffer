#!/usr/bin/env python3
"""
Thin launcher for the Tibia sniffer GUI.

This file simply delegates to `tibia_gui.py`, which contains the
fully-featured GUI. Run either:
  python3 gui_sniffer.py
or
  python3 tibia_gui.py
"""
from tibia_gui import main

if __name__ == "__main__":
    main()
