# Tibia OPCODE + Byte extractor by WhiteCrixu

Small Python tool to extract an "opcode" and a following "byte" from Tibia TCP payloads.

Files added
- `extract_tibia.py` — main script (pcap reader + live sniffer)
- `requirements.txt` — scapy dependency
- `tibia_gui.py` — clean Tkinter GUI for live sniffing (recommended)
- `gui_sniffer.py` — alternate GUI; prefer `tibia_gui.py`

Quick usage

1) Install dependency (prefer a venv):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2) Parse a pcap:

```bash
python3 extract_tibia.py --pcap capture.pcap
```

3) Live sniff (requires privileges):

```bash
sudo python3 extract_tibia.py --iface eth0
```

Profiles for Tibia ports

- login (port 7172, plaintext frame):

```bash
python3 extract_tibia.py --iface <iface> --profile login --tibia-frame --verbose
```

- game (port 7171, XTEA):

```bash
python3 extract_tibia.py --iface <iface> --profile game --tibia-frame --xtea-key 00112233445566778899AABBCCDDEEFF --verbose

# or let the sniffer attempt auto-extraction (Linux root only)
python3 extract_tibia.py --iface <iface> --profile game --verbose
```

GUI usage

- Start the GUI:

```bash
python3 tibia_gui.py
```

- In the GUI, choose interface type (any/wlan/eth), refresh and pick an interface, set port (any TCP port, default 7171), and offsets (opcode offset, byte offset). Click Start to begin capture. Lines will stream in the log with timestamp, src/dst, opcode, and byte. Click Stop to end.

Permissions for live capture

Capturing packets requires elevated privileges on Linux. Options:
- Run as root: `sudo python3 tibia_gui.py`
- OR grant capabilities to your Python interpreter (recommended to do this on the venv's python):

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```
If you use a virtualenv, run `which python3` inside the venv and apply setcap to that path. If your venv python is a symlink to `/usr/bin/python3.XX`, apply setcap to the resolved binary (e.g., `/usr/bin/python3.12`).

Windows capture requirements

- Install Npcap (https://nmap.org/npcap/) with “WinPcap API-compatible mode”.
- Use an elevated PowerShell (Run as Administrator) if capture fails.
- You can also use the prebuilt `.exe` releases for zero Python setup.
- Auto XTEA extraction is not available on Windows; provide the key manually.

Alternative workflow without privileges

You can capture to a pcap with tcpdump (requires sudo once) and analyze offline:

```bash
sudo tcpdump -i <iface> tcp port 7171 -w tibia.pcap
python3 extract_tibia.py --pcap tibia.pcap
```

Interface selection
- List interfaces:

```bash
python3 extract_tibia.py --list-ifaces
```

- List only wlan or eth-like interfaces:

```bash
python3 extract_tibia.py --list-ifaces --iface-type wlan
```

- Interactive selection:

```bash
python3 extract_tibia.py --select --iface-type wlan
```


4) Run built-in test:

```bash
python3 extract_tibia.py --test
```

Configurable offsets
- `--opcode-offset` and `--opcode-len` control where the opcode is read from inside the TCP payload
- `--byte-offset` and `--byte-len` control the other byte

Contract (inputs/outputs)
- Inputs: pcap file or network interface; payload offsets & lengths
- Outputs: printed lines per packet containing timestamp, addresses, opcode integer and raw bytes, and other byte

Edge cases
- Skips packets without TCP Raw payload
- Prints nothing for payloads shorter than the requested offsets
- Live sniffing requires root or CAP_NET_RAW

Next steps
- Add support for encrypted/compressed payloads (if Tibia uses obfuscation)
- Add JSON/CSV output option
- Add more tests and CI integration

Release (prebuilt binaries)

- Download the latest release from GitHub Releases:
	- Linux: `tibia-sniffer` and `tibia-sniffer-gui`
	- Windows: `tibia-sniffer.exe` and `tibia-sniffer-gui.exe`
- On Linux, make the binary executable:

```bash
chmod +x tibia-sniffer tibia-sniffer-gui
```

- Run CLI:

```bash
./tibia-sniffer --iface <iface> --profile login --tibia-frame --verbose
```

- Run GUI:

```bash
./tibia-sniffer-gui
```

Creating a new release (maintainers)

1) Update `VERSION` and `CHANGELOG.md` as needed
2) Create a tag and push:

```bash
git tag v$(cat VERSION)
git push origin v$(cat VERSION)
```

GitHub Actions will build and attach binaries to the tagged release automatically.
