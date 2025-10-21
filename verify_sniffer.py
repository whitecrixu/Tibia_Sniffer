#!/usr/bin/env python3
"""
Skrypt weryfikacyjny - wysyła znane pakiety Tibia i sprawdza czy sniffer poprawnie rozpoznaje OPCODE i BYTE

Test cases:
1. Pakiet z opcode=0x35 (53), byte=0x01 (1) - ruch gracza
2. Pakiet z opcode=0x14 (20), byte=0xFF (255) - inny przykład
3. Pakiet bez framing (raw) - opcode na pozycji 0, byte na pozycji 1
"""

import sys
import time
import subprocess
import tempfile
from scapy.all import wrpcap, IP, TCP, Raw, Ether

def create_test_pcap():
    """Tworzy pcap z znanymi pakietami testowymi"""
    packets = []
    
    # Test 1: Tibia framed packet - opcode=0x35 (53), byte=0x01 (1)
    # Format: [len:2 bytes LE][opcode:1][byte:1]
    payload1 = bytes([
        0x02, 0x00,  # len=2 (little-endian)
        0x35,        # opcode=53
        0x01         # byte=1
    ])
    pkt1 = Ether()/IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12345, dport=7172, flags='PA')/Raw(payload1)
    packets.append(pkt1)
    
    # Test 2: Tibia framed packet - opcode=0x14 (20), byte=0xFF (255)
    payload2 = bytes([
        0x02, 0x00,  # len=2
        0x14,        # opcode=20
        0xFF         # byte=255
    ])
    pkt2 = Ether()/IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12346, dport=7172, flags='PA')/Raw(payload2)
    packets.append(pkt2)
    
    # Test 3: Tibia framed packet - opcode=0x64 (100), byte=0x32 (50)
    payload3 = bytes([
        0x02, 0x00,  # len=2
        0x64,        # opcode=100
        0x32         # byte=50
    ])
    pkt3 = Ether()/IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12347, dport=7172, flags='PA')/Raw(payload3)
    packets.append(pkt3)
    
    # Test 4: Raw packet bez framing (stary format)
    payload4 = bytes([
        0xAA,        # opcode=170 na pozycji 0
        0xBB,        # byte=187 na pozycji 1
        0xCC, 0xDD   # dodatkowe dane
    ])
    pkt4 = Ether()/IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12348, dport=7171, flags='PA')/Raw(payload4)
    packets.append(pkt4)
    
    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
    wrpcap(tmpfile.name, packets)
    tmpfile.close()
    return tmpfile.name

def run_sniffer_on_pcap(pcap_file, use_tibia_frame=False):
    """Uruchamia sniffer na pcap i zwraca wyjście"""
    cmd = [
        '/home/crixu/Tibia_Sniffer/.venv/bin/python',
        '/home/crixu/Tibia_Sniffer/extract_tibia.py',
        '--pcap', pcap_file
    ]
    
    if use_tibia_frame:
        cmd.append('--tibia-frame')
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def parse_output(output):
    """Parsuje output sniffera i wyciąga OPCODE i BYTE"""
    results = []
    for line in output.split('\n'):
        if 'OPCODE=' in line and 'BYTE=' in line:
            # Wyciągnij opcode i byte z linii
            opcode_part = line.split('OPCODE=')[1].split('|')[0].strip()
            byte_part = line.split('BYTE=')[1].split('|')[0].strip() if 'BYTE=' in line else ''
            
            # Weź tylko wartość int (przed nawiasem)
            opcode = int(opcode_part.split('(')[0])
            byte_val = int(byte_part.split('(')[0]) if byte_part and byte_part.split('(')[0] else None
            
            results.append({'opcode': opcode, 'byte': byte_val})
    return results

def main():
    print("=" * 70)
    print("WERYFIKACJA SNIFFERA TIBIA - Test poprawności OPCODE i BYTE")
    print("=" * 70)
    
    # Oczekiwane wyniki
    expected_tibia_frame = [
        {'opcode': 53, 'byte': 1, 'desc': 'Test 1: opcode=0x35 (53), byte=0x01 (1)'},
        {'opcode': 20, 'byte': 255, 'desc': 'Test 2: opcode=0x14 (20), byte=0xFF (255)'},
        {'opcode': 100, 'byte': 50, 'desc': 'Test 3: opcode=0x64 (100), byte=0x32 (50)'},
    ]
    
    expected_raw = [
        {'opcode': 170, 'byte': 187, 'desc': 'Test 4: raw opcode=0xAA (170), byte=0xBB (187)'}
    ]
    
    print("\n1. Tworzenie testowego pcap...")
    pcap_file = create_test_pcap()
    print(f"   ✓ Utworzono: {pcap_file}")
    
    # Test 1: Tibia framing
    print("\n2. Test z --tibia-frame (port 7172):")
    print("-" * 70)
    output_framed = run_sniffer_on_pcap(pcap_file, use_tibia_frame=True)
    results_framed = parse_output(output_framed)
    
    print("\n   Wyniki:")
    passed = 0
    failed = 0
    
    for i, (expected, actual) in enumerate(zip(expected_tibia_frame, results_framed[:3])):
        match = expected['opcode'] == actual['opcode'] and expected['byte'] == actual['byte']
        status = "✓ PASS" if match else "✗ FAIL"
        
        print(f"\n   {expected['desc']}")
        print(f"      Oczekiwano: opcode={expected['opcode']}, byte={expected['byte']}")
        print(f"      Otrzymano:  opcode={actual['opcode']}, byte={actual['byte']}")
        print(f"      Status: {status}")
        
        if match:
            passed += 1
        else:
            failed += 1
    
    # Test 2: Raw format
    print("\n3. Test bez --tibia-frame (port 7171, raw offsets):")
    print("-" * 70)
    output_raw = run_sniffer_on_pcap(pcap_file, use_tibia_frame=False)
    results_raw = parse_output(output_raw)
    
    if len(results_raw) >= 4:
        actual_raw = results_raw[3]  # 4ty pakiet
        expected = expected_raw[0]
        match = expected['opcode'] == actual_raw['opcode'] and expected['byte'] == actual_raw['byte']
        status = "✓ PASS" if match else "✗ FAIL"
        
        print(f"\n   {expected['desc']}")
        print(f"      Oczekiwano: opcode={expected['opcode']}, byte={expected['byte']}")
        print(f"      Otrzymano:  opcode={actual_raw['opcode']}, byte={actual_raw['byte']}")
        print(f"      Status: {status}")
        
        if match:
            passed += 1
        else:
            failed += 1
    
    # Podsumowanie
    print("\n" + "=" * 70)
    print("PODSUMOWANIE:")
    print(f"  ✓ Testy zaliczone: {passed}")
    print(f"  ✗ Testy niezaliczone: {failed}")
    
    if failed == 0:
        print("\n  🎉 WSZYSTKIE TESTY ZALICZONE - Sniffer działa poprawnie!")
        print("  GUI używa tego samego backendu, więc też będzie działać poprawnie.")
    else:
        print("\n  ⚠️  NIEKTÓRE TESTY NIE PRZESZŁY - sprawdź konfigurację sniffera")
    
    print("=" * 70)
    
    # Czyszczenie
    import os
    try:
        os.unlink(pcap_file)
    except:
        pass
    
    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
