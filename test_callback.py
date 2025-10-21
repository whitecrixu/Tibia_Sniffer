#!/usr/bin/env python3
"""Test sniffer callback without GUI - verify on_event is called"""
import threading
import time
import extract_tibia as et

def _make_args(iface, port, tibia_frame=False, verbose=False):
    a = type('A', (), {})()
    a.iface = iface
    a.port = port
    a.opcode_offset = 0
    a.opcode_len = 1
    a.byte_offset = 1
    a.byte_len = 1
    a.count = 1  # Just capture one packet
    a.output = 'text'
    a.outfile = None
    a.verbose = verbose
    a.tibia_frame = tibia_frame
    a.xtea_key_bytes = None
    a.ports = None
    return a

def main():
    print("[TEST] Starting callback test...")
    
    received_lines = []
    
    def on_evt(line: str):
        print(f"[TEST] Callback received: {line[:80]}")
        received_lines.append(line)
    
    args = _make_args('lo', 7172, tibia_frame=True, verbose=True)
    stop_event = threading.Event()
    
    # Start sniffer in background
    def run_sniffer():
        try:
            et.live_sniff(args, stop_event=stop_event, on_event=on_evt)
        except Exception as e:
            print(f"[TEST] Sniffer error: {e}")
    
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()
    
    print("[TEST] Waiting 2 seconds for sniffer to initialize...")
    time.sleep(2)
    
    # Send test packet
    print("[TEST] Sending test packet...")
    from scapy.all import send, IP, TCP, Raw, conf
    conf.use_pcap = True
    conf.sniff_promisc = False
    payload = bytes([0x02,0x00,0x35,0x01])
    pkt = IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=48000, dport=7172, flags='PA')/Raw(payload)
    send(pkt, verbose=False)
    print("[TEST] Test packet sent")
    
    # Wait for capture
    time.sleep(2)
    stop_event.set()
    time.sleep(1)
    
    print(f"\n[TEST] Results:")
    print(f"  Callback called: {len(received_lines)} time(s)")
    if received_lines:
        print(f"  Lines received:")
        for line in received_lines:
            print(f"    {line}")
    else:
        print("  ❌ NO LINES RECEIVED - callback not working!")

if __name__ == '__main__':
    main()
