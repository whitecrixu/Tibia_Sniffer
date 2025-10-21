#!/usr/bin/env python3
"""Clean Tkinter GUI for the Tibia sniffer (alternate module)

This file is a single-file GUI that uses extract_tibia.live_sniff. It is
created as a separate module to avoid issues with any corrupted gui_sniffer.py
that may exist in the workspace. Run with:

    python3 tibia_gui.py

"""
import threading
import binascii
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import extract_tibia as et
import zlib
import queue
from collections import defaultdict


def _make_args(iface, port, op_offset, byte_offset, output, outfile, tibia_frame=False, xtea_key_bytes=None, ports_list=None, verbose=False):
    a = type('A', (), {})()
    a.iface = iface
    a.port = port
    a.opcode_offset = op_offset
    a.opcode_len = 1
    a.byte_offset = byte_offset
    a.byte_len = 1
    a.count = None
    a.output = output
    a.outfile = outfile
    a.verbose = bool(verbose)
    a.tibia_frame = tibia_frame
    a.xtea_key_bytes = xtea_key_bytes
    a.ports = ports_list
    return a


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        root.title('Tibia Sniffer GUI (clean) by WhiteCrixu')

        # Window config: resizable & grid weights
        root.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)

        frm = ttk.Frame(root, padding=8)
        frm.grid(sticky='nsew')
        for c in range(4):
            frm.columnconfigure(c, weight=1)
        # Last row (log) grows
        for r in range(0, 11):
            frm.rowconfigure(r, weight=0)
        frm.rowconfigure(9, weight=1)

        ttk.Label(frm, text='Interface type:').grid(column=0, row=0, sticky='w')
        self.iftype = tk.StringVar(value='any')
        ttk.Combobox(frm, textvariable=self.iftype, values=['any', 'wlan', 'eth'], width=12).grid(column=1, row=0)
        ttk.Button(frm, text='Refresh', command=self.refresh_ifaces).grid(column=2, row=0)
        self.iface_list = ttk.Combobox(frm, values=[], width=30)
        self.iface_list.grid(column=0, row=1, columnspan=2, sticky='we')

        ttk.Label(frm, text='Port:').grid(column=2, row=1, sticky='w')
        self.port = tk.StringVar(value='7172')
        ttk.Entry(frm, textvariable=self.port, width=8).grid(column=3, row=1)

        # Multi-ports
        ttk.Label(frm, text='Ports (comma):').grid(column=2, row=2, sticky='w')
        self.ports_str = tk.StringVar(value='')
        ttk.Entry(frm, textvariable=self.ports_str, width=16).grid(column=3, row=2)

        ttk.Label(frm, text='Opcode offset:').grid(column=0, row=3, sticky='w')
        self.op_offset = tk.IntVar(value=0)
        ttk.Entry(frm, textvariable=self.op_offset, width=6).grid(column=1, row=3)

        ttk.Label(frm, text='Byte offset:').grid(column=0, row=4, sticky='w')
        self.byte_offset = tk.IntVar(value=1)
        ttk.Entry(frm, textvariable=self.byte_offset, width=6).grid(column=1, row=4)

        ttk.Label(frm, text='Output:').grid(column=0, row=5, sticky='w')
        self.output = tk.StringVar(value='text')
        ttk.Combobox(frm, textvariable=self.output, values=['text', 'json', 'csv', 'all'], width=12).grid(column=1, row=5)
        ttk.Button(frm, text='Outfile', command=self.choose_outfile).grid(column=2, row=5)
        self.outfile = tk.StringVar()

        # Tibia frame + XTEA key
        self.tibia_frame = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text='Tibia frame', variable=self.tibia_frame).grid(column=0, row=6, sticky='w')
        # Verbose toggle
        self.verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text='Verbose', variable=self.verbose).grid(column=0, row=6, sticky='e')
        ttk.Label(frm, text='XTEA key (hex 32):').grid(column=1, row=6, sticky='e')
        self.xtea_key = tk.StringVar()
        ttk.Entry(frm, textvariable=self.xtea_key, width=36).grid(column=2, row=6, columnspan=2, sticky='we')

        # Process scan for XTEA
        ttk.Label(frm, text='Process name/PID:').grid(column=0, row=7, sticky='w')
        self.proc_name = tk.StringVar(value='Tibia')
        ttk.Entry(frm, textvariable=self.proc_name, width=20).grid(column=1, row=7, sticky='we')
        ttk.Button(frm, text='Scan XTEA', command=self.scan_xtea).grid(column=2, row=7, sticky='e')
        self.candidates = ttk.Combobox(frm, values=[], width=40)
        self.candidates.grid(column=3, row=7, sticky='we')
        ttk.Button(frm, text='Validate candidates', command=self.validate_candidates).grid(column=2, row=8, sticky='e')

        # Controls
        self.start_btn = ttk.Button(frm, text='Start', command=self.start)
        self.start_btn.grid(column=0, row=8, sticky='w')
        self.stop_btn = ttk.Button(frm, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.grid(column=1, row=8, sticky='w')
        self.max_btn = ttk.Button(frm, text='Maximize', command=self.maximize)
        self.max_btn.grid(column=2, row=8, sticky='e')
        self.full_btn = ttk.Button(frm, text='Fullscreen', command=self.toggle_fullscreen)
        self.full_btn.grid(column=3, row=8, sticky='e')

        # Split log area: left log, right opcode stats
        log_frame = ttk.Frame(frm)
        log_frame.grid(column=0, row=9, columnspan=4, sticky='nsew')
        log_frame.columnconfigure(0, weight=3)
        log_frame.columnconfigure(1, weight=2)
        log_frame.rowconfigure(0, weight=1)

        self.log = scrolledtext.ScrolledText(log_frame, width=60, height=18)
        self.log.grid(column=0, row=0, sticky='nsew', padx=(0,6))

        # Opcode stats Treeview
        stats_frame = ttk.Frame(log_frame)
        stats_frame.grid(column=1, row=0, sticky='nsew')
        stats_cols = ('dir','opcode','name','count')
        self.stats = ttk.Treeview(stats_frame, columns=stats_cols, show='headings', height=18)
        for c, w in zip(stats_cols, (6,8,24,6)):
            self.stats.heading(c, text=c.upper())
            self.stats.column(c, width=w*8, anchor='w')
        self.stats.grid(column=0, row=0, sticky='nsew')
        stats_frame.rowconfigure(0, weight=1)
        stats_frame.columnconfigure(0, weight=1)
        self._opcode_counts = defaultdict(int)  # key=(dir, opcode, name)

        self._stop_event = threading.Event()
        self.thread = None
        self._fullscreen = False
        # mapping state
        self._opcode_map = None
        self._server_opcode_map = None
    # Queue for thread-safe logging from sniffer thread (text and objects)
        self._log_queue = queue.Queue()
        self._events_structured = []  # captured structured events for export
        self._process_log_queue()
        self.refresh_ifaces()

        # Add mapping loader row under log for compactness
        mapfrm = ttk.Frame(frm)
        mapfrm.grid(column=0, row=10, columnspan=4, sticky='we', pady=(6,0))
        mapfrm.columnconfigure(1, weight=1)
        ttk.Label(mapfrm, text='crystalserver path:').grid(column=0, row=0, sticky='w')
        self.cs_path = tk.StringVar(value='/home/crixu/Tibia_Sniffer/crystalserver')
        ttk.Entry(mapfrm, textvariable=self.cs_path).grid(column=1, row=0, sticky='we')
        ttk.Button(mapfrm, text='Load mapping', command=self.load_mapping).grid(column=2, row=0)
        # Mapping status label
        self.map_status = ttk.Label(mapfrm, text='Mapping: none')
        self.map_status.grid(column=0, row=1, columnspan=3, sticky='w')

        # Export/Clear controls
        ctrlfrm = ttk.Frame(frm)
        ctrlfrm.grid(column=0, row=11, columnspan=4, sticky='we', pady=(6,0))
        ttk.Button(ctrlfrm, text='Export JSON', command=self.export_events_json).grid(column=0, row=0, sticky='w')
        ttk.Button(ctrlfrm, text='Clear Log/Stats', command=self.clear_log_stats).grid(column=1, row=0, sticky='w', padx=(6,0))

    def _append_log(self, text: str):
        """Append text to log widget - MUST be called from main thread"""
        try:
            self.log.insert('end', text)
            if not text.endswith('\n'):
                self.log.insert('end', '\n')
            self.log.see('end')
            self.log.update_idletasks()
        except Exception as ex:
            print(f"[GUI] _append_log error: {ex}")
    
    def _process_log_queue(self):
        """Process pending log messages from queue - runs in main thread"""
        try:
            while True:
                item = self._log_queue.get_nowait()
                if isinstance(item, str):
                    self._append_log(item)
                elif isinstance(item, dict):
                    # structured event
                    self._append_log(
                        f"{item.get('timestamp','')} {item.get('src')}:{item.get('sport')} -> {item.get('dst')}:{item.get('dport')}"
                        + (f" [{item.get('service')}]" if item.get('service') else '')
                        + f" | OPCODE={item.get('opcode_int')}({item.get('opcode_raw')})"
                        + (f"[{item.get('opcode_name')}]" if item.get('opcode_name') else '')
                        + f" | BYTE={item.get('byte_int')}({item.get('byte_raw')})"
                        + (f"[{item.get('byte_name')}]" if item.get('byte_name') else '')
                    )
                    # update stats
                    key = (item.get('direction') or '?', item.get('opcode_int'), item.get('opcode_name') or '')
                    self._opcode_counts[key] += 1
                    # store structured event for export
                    self._events_structured.append(item)
                    self._refresh_stats_view()
        except queue.Empty:
            pass
        # Schedule next check in 100ms
        self.root.after(100, self._process_log_queue)

    def _refresh_stats_view(self):
        # naive refresh: clear and repopulate
        for i in self.stats.get_children():
            self.stats.delete(i)
        # sort by count desc
        for (d, op, name), cnt in sorted(self._opcode_counts.items(), key=lambda x: -x[1]):
            self.stats.insert('', 'end', values=(d, op, name, cnt))

    def scan_xtea(self):
        # Run scan in background to keep UI responsive
        def _scan():
            try:
                try:
                    import xtea_mem_extractor as xme
                except Exception as e:
                    self.log.insert('end', f'Cannot import xtea_mem_extractor: {e}\n')
                    return
                target = (self.proc_name.get() or '').strip()
                if not target:
                    self.log.insert('end', 'Enter process name or PID\n')
                    return
                # Resolve PID
                pid = None
                if target.isdigit():
                    pid = int(target)
                else:
                    pid = xme._find_pid_by_name(target)
                if not pid:
                    self.log.insert('end', f'Process not found for: {target}\n')
                    return
                # Attach
                try:
                    xme._ptrace(16, pid)  # PTRACE_ATTACH
                except Exception as e:
                    self.log.insert('end', f'ptrace attach failed: {e}\nHint: run as root and set ptrace_scope=0\n')
                    return
                try:
                    if not xme._wait_stopped(pid):
                        self.log.insert('end', 'Process did not stop after attach\n')
                        return
                    counts = xme._scan_candidates(pid, max_total_bytes=64*1024*1024)
                    cand = [k.hex().upper() for k, _ in counts.most_common(30)]
                    self.candidates['values'] = cand
                    if cand:
                        # auto-select top and fill XTEA field
                        self.candidates.set(cand[0])
                        self.xtea_key.set(cand[0])
                        self.log.insert('end', f'XTEA candidates found: {len(cand)} (auto-selected top)\n')
                    else:
                        self.log.insert('end', 'No candidates found\n')
                finally:
                    try:
                        xme._ptrace(17, pid)  # PTRACE_DETACH
                    except Exception:
                        pass
            except Exception as e:
                self.log.insert('end', f'Scan error: {e}\n')

        threading.Thread(target=_scan, daemon=True).start()

    def _capture_game_payloads(self, iface: str, ports_list):
        try:
            from scapy.all import sniff, TCP, Raw, conf
        except Exception as e:
            self.log.insert('end', f'Scapy not available: {e}\n')
            return []
        # Build filter to prioritize 7172 (game)
        ports = ports_list or []
        if not ports:
            ports = [7172]
        elif 7172 not in ports:
            ports = ports + [7172]
        flt = "tcp and (" + " or ".join(f"port {p}" for p in ports) + ")"
        samples = []
        def _collect(pkt):
            nonlocal samples
            try:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    samples.append(bytes(pkt[Raw].load))
            except Exception:
                pass
        try:
            # prefer pcap backend and non-promiscuous (loopback-friendly)
            try:
                conf.use_pcap = True
                conf.sniff_promisc = False
            except Exception:
                pass
            sniff(filter=flt, prn=_collect, iface=iface, count=40, timeout=12, store=False)
        except Exception as e:
            self.log.insert('end', f'Capture error: {e}\n')
        self.log.insert('end', f'Captured samples: {len(samples)}\n')
        return samples

    def _score_xtea_key(self, key_bytes: bytes, payloads: list[bytes]) -> int:
        score = 0
        for payload in payloads:
            if payload is None or len(payload) < 10:
                continue
            enc = payload[2:]
            n = len(enc) - (len(enc) % 8)
            if n < 8:
                continue
            try:
                dec = et.xtea_decrypt_le(enc[:n], key_bytes)
            except Exception:
                continue
            if len(dec) < 4:
                continue
            chk = int.from_bytes(dec[:2], 'little')
            body = dec[2:]
            if not body:
                continue
            sum16 = sum(body) & 0xFFFF
            adl16 = zlib.adler32(body) & 0xFFFF
            # crude crc16-ccitt
            crc = 0xFFFF
            for b in body:
                crc ^= (b << 8)
                for _ in range(8):
                    if crc & 0x8000:
                        crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                    else:
                        crc = (crc << 1) & 0xFFFF
            if chk in (sum16, adl16, crc):
                score += 1
        return score

    def validate_candidates(self):
        # Run validation in background
        def _validate():
            try:
                iface = self.iface_list.get() or 'lo'
                ports_list = None
                ports_raw = (self.ports_str.get() or '').strip()
                if ports_raw:
                    try:
                        ports_list = [int(p.strip()) for p in ports_raw.split(',') if p.strip()]
                    except Exception:
                        ports_list = None
                self.log.insert('end', 'Capturing sample packets for validation...\n')
                payloads = self._capture_game_payloads(iface, ports_list)
                if not payloads:
                    self.log.insert('end', 'No samples captured. Interact in game and try again.\n')
                    return
                cands = list(self.candidates['values'])
                if not cands:
                    self.log.insert('end', 'No candidates to validate. Run Scan XTEA first.\n')
                    return
                best = None
                best_score = 0
                for hexkey in cands[:20]:
                    try:
                        keyb = binascii.unhexlify(hexkey)
                    except Exception:
                        continue
                    sc = self._score_xtea_key(keyb, payloads)
                    self.log.insert('end', f'Key {hexkey[:8]}... score={sc}\n')
                    if sc > best_score:
                        best_score = sc
                        best = hexkey
                if best and best_score > 0:
                    self.xtea_key.set(best)
                    self.candidates.set(best)
                    self.log.insert('end', f'Selected best key (score={best_score})\n')
                else:
                    self.log.insert('end', 'Could not determine best key (no positive score).\n')
            except Exception as e:
                self.log.insert('end', f'Validate error: {e}\n')
        threading.Thread(target=_validate, daemon=True).start()

    def refresh_ifaces(self):
        try:
            ifaces = et.list_interfaces(self.iftype.get())
        except Exception:
            ifaces = []
        self.iface_list['values'] = ifaces
        if ifaces:
            # Prefer loopback 'lo' if available to match working CLI example
            pref = 'lo'
            if pref in ifaces:
                self.iface_list.set(pref)
            else:
                self.iface_list.set(ifaces[0])
        else:
            # Fallback when interface listing failed (e.g., netifaces missing): default to 'lo'
            try:
                self.iface_list.set('lo')
            except Exception:
                pass

    def choose_outfile(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv')
        if path:
            self.outfile.set(path)

    def start(self):
        # Default to 'lo' if nothing selected, to mirror working CLI usage
        sel = self.iface_list.get()
        iface = (sel.strip() if isinstance(sel, str) else '') or 'lo'
        try:
            port = int(self.port.get())
        except Exception:
            port = 7171
        # Parse XTEA key if provided
        xtea_bytes = None
        key = (self.xtea_key.get() or '').strip()
        if key:
            try:
                xtea_bytes = binascii.unhexlify(key)
            except Exception:
                self.log.insert('end', 'Invalid XTEA key hex\n')
                xtea_bytes = None
        # Parse multi-ports
        ports_list = None
        ports_raw = (self.ports_str.get() or '').strip()
        if ports_raw:
            try:
                ports_list = [int(p.strip()) for p in ports_raw.split(',') if p.strip()]
            except Exception:
                self.log.insert('end', 'Invalid ports list\n')
                ports_list = None

        args = _make_args(
            iface,
            port,
            int(self.op_offset.get()),
            int(self.byte_offset.get()),
            self.output.get(),
            self.outfile.get() or None,
            tibia_frame=bool(self.tibia_frame.get()),
            xtea_key_bytes=xtea_bytes,
            ports_list=ports_list,
            verbose=bool(self.verbose.get()),
        )
        # attach mapping if loaded
        if self._opcode_map is not None:
            args.opcode_map = self._opcode_map
        if self._server_opcode_map is not None:
            args.server_opcode_map = self._server_opcode_map
        self._stop_event.clear()

        def run():
            def on_evt(line: str):
                try:
                    self._log_queue.put(line)
                except Exception as ex:
                    print(f"[GUI] on_evt queue error: {ex}")
            def on_evt_obj(obj: dict):
                try:
                    self._log_queue.put(obj)
                except Exception as ex:
                    print(f"[GUI] on_evt_obj queue error: {ex}")
            self._log_queue.put("[DEBUG] Sniffer thread started, waiting for packets...")
            try:
                et.live_sniff(args, stop_event=self._stop_event, on_event=on_evt, on_event_obj=on_evt_obj)
            except Exception as e:
                self._log_queue.put(f'Error: {e}')
            finally:
                self.start_btn['state'] = 'normal'
                self.stop_btn['state'] = 'disabled'

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.start_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self._append_log(f'Started on {iface or "any"}:{port}  frame={bool(self.tibia_frame.get())}  verbose={bool(self.verbose.get())}')

    def stop(self):
        self._stop_event.set()
        self.log.insert('end', 'Stop requested\n')
        self.start_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'

    def maximize(self):
        try:
            # Try platform zoomed (Windows/most WM)
            self.root.state('zoomed')
        except Exception:
            # Fallback: expand geometry to screen
            try:
                w = self.root.winfo_screenwidth()
                h = self.root.winfo_screenheight()
                self.root.geometry(f"{w}x{h}+0+0")
            except Exception:
                pass

    def toggle_fullscreen(self):
        self._fullscreen = not self._fullscreen
        try:
            self.root.attributes('-fullscreen', self._fullscreen)
        except Exception:
            pass

    def load_mapping(self):
        path = (self.cs_path.get() or '').strip()
        if not path:
            self.log.insert('end', 'Provide crystalserver root path\n')
            return
        try:
            mapping = et.load_opcode_map_from_crystalserver(path, verbose=False)
            server_map = et.load_server_opcode_map_from_crystalserver(path, verbose=False)
            if not mapping and not server_map:
                self.log.insert('end', 'No mapping extracted. Check path.\n')
                return
            self._opcode_map = mapping or {}
            self._server_opcode_map = server_map or {}
            self.log.insert('end', f'Loaded mapping: client {len(self._opcode_map)} / server {len(self._server_opcode_map)} entries\n')
            try:
                self.map_status.config(text=f"Mapping: client={len(self._opcode_map)} server={len(self._server_opcode_map)}")
            except Exception:
                pass
        except Exception as e:
            self.log.insert('end', f'Mapping load error: {e}\n')

    def export_events_json(self):
        try:
            import json
            path = filedialog.asksaveasfilename(defaultextension='.json')
            if not path:
                return
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self._events_structured, f, indent=2, ensure_ascii=False)
            self._append_log(f'Exported {len(self._events_structured)} events to {path}')
        except Exception as e:
            self._append_log(f'Export error: {e}')

    def clear_log_stats(self):
        try:
            self.log.delete('1.0', 'end')
            self._opcode_counts.clear()
            self._refresh_stats_view()
            self._events_structured.clear()
            self._append_log('[Cleared] Log, stats and events')
        except Exception as e:
            self._append_log(f'Clear error: {e}')


def main():
    root = tk.Tk()
    SnifferGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
