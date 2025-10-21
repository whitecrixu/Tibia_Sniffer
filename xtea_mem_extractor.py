#!/usr/bin/env python3
"""
Experimental XTEA key extractor from a running Tibia client process (Linux).

WARNING:
- Requires root and ptrace permissions (echo 0 > /proc/sys/kernel/yama/ptrace_scope)
- Best-effort: scans rw private memory segments and reports candidate 16-byte keys
- For reliable results, prefer RSA-based extraction (if you control server) or manual key

Usage examples:
  sudo python3 xtea_mem_extractor.py --proc-name Tibia --top 20
  sudo python3 xtea_mem_extractor.py --pid 12345 --top 50

Optionally, you can capture a few encrypted frames and attempt a rough validation
score against candidates later using extract_tibia.py.
"""
import argparse
import os
import sys
import time
import ctypes
import signal
from collections import Counter


PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def _ptrace(request: int, pid: int, addr=0, data=0):
    # ptrace returns 0 on success, -1 on failure and sets errno
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    res = libc.ptrace(ctypes.c_long(request), ctypes.c_int(pid), ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res == -1:
        err = ctypes.get_errno()
        raise OSError(err, f"ptrace({request}) failed: errno={err}")


def _wait_stopped(pid: int, timeout=5.0):
    start = time.time()
    # Try non-blocking wait loop first
    while time.time() - start < timeout:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                if os.WIFSTOPPED(status):
                    return True
                # If it's not stopped but we consumed a status, break to avoid missing state
                break
        except ChildProcessError:
            return False
        time.sleep(0.05)
    # Fallback: try a blocking wait with small timeout using alarm
    try:
        def _alarm_handler(signum, frame):
            raise TimeoutError()
        old = signal.signal(signal.SIGALRM, _alarm_handler)
        try:
            signal.alarm(int(max(1, timeout - (time.time() - start))))
            wpid, status = os.waitpid(pid, 0)
            signal.alarm(0)
            return os.WIFSTOPPED(status)
        finally:
            signal.signal(signal.SIGALRM, old)
    except Exception:
        return False


def _find_pid_by_name(name: str):
    name_low = name.lower()
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        pid = int(d)
        try:
            with open(f'/proc/{pid}/comm', 'r') as f:
                comm = f.read().strip()
            if comm.lower().startswith(name_low):
                return pid
        except Exception:
            continue
    return None


def _iter_rw_private_maps(pid: int):
    maps_path = f'/proc/{pid}/maps'
    with open(maps_path, 'r') as f:
        for line in f:
            # Example: 55c4d0d2d000-55c4d0d4f000 rw-p 00000000 00:00 0                          [heap]
            parts = line.split()
            if not parts:
                continue
            addr, perms = parts[0], parts[1]
            pathname = parts[-1] if len(parts) >= 6 else ''
            if 'rw' not in perms or 'p' not in perms:
                continue
            # Skip stacks to reduce noise
            if pathname.startswith('[') and 'stack' in pathname:
                continue
            start_s, end_s = addr.split('-')
            start = int(start_s, 16)
            end = int(end_s, 16)
            size = end - start
            yield (start, size, pathname)


def _scan_candidates(pid: int, max_total_bytes=64*1024*1024, stride=4):
    mem_path = f'/proc/{pid}/mem'
    fd = os.open(mem_path, os.O_RDONLY)
    counts = Counter()
    total_read = 0
    try:
        for start, size, name in _iter_rw_private_maps(pid):
            if total_read >= max_total_bytes:
                break
            # Read in chunks
            offset = 0
            chunk_size = 256*1024
            while offset < size:
                if total_read >= max_total_bytes:
                    break
                to_read = min(chunk_size, size - offset)
                try:
                    data = os.pread(fd, to_read, start + offset)
                except OSError:
                    break
                if not data:
                    break
                total_read += len(data)
                # slide over chunk to find 16-byte sequences at 4-byte alignment
                for i in range(0, len(data) - 16 + 1, stride):
                    key = data[i:i+16]
                    # discard trivial keys (all zeros)
                    if key == b'\x00' * 16:
                        continue
                    counts[key] += 1
                offset += to_read
    finally:
        os.close(fd)
    return counts


def main():
    ap = argparse.ArgumentParser(description='Experimental XTEA candidate extractor (Linux)')
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--pid', type=int, help='PID of the Tibia client process')
    g.add_argument('--proc-name', help='Process name prefix to match (e.g., Tibia)')
    ap.add_argument('--top', type=int, default=20, help='Show top-N candidate keys')
    ap.add_argument('--max-bytes', type=int, default=64*1024*1024, help='Max total bytes to scan across maps')
    ap.add_argument('--ptrace-scope', action='store_true', help='Print note about /proc/sys/kernel/yama/ptrace_scope if attach fails')
    args = ap.parse_args()

    pid = args.pid
    if not pid and args.proc_name:
        pid = _find_pid_by_name(args.proc_name)
        if not pid:
            print(f'Process starting with name {args.proc_name!r} not found')
            sys.exit(1)

    # ptrace attach
    try:
        _ptrace(PTRACE_ATTACH, pid)
    except Exception as e:
        print(f'ptrace attach failed: {e}')
        if args.ptrace_scope:
            print('Hint: run as root and set echo 0 > /proc/sys/kernel/yama/ptrace_scope (temporary)')
        sys.exit(2)

    try:
        if not _wait_stopped(pid):
            print('Process did not stop after attach in time')
            sys.exit(3)
        counts = _scan_candidates(pid, max_total_bytes=args.max_bytes)
        print(f'Total unique candidates: {len(counts)}')
        for key, cnt in counts.most_common(args.top):
            print(f'{key.hex().upper()}  count={cnt}')
    finally:
        try:
            _ptrace(PTRACE_DETACH, pid)
        except Exception:
            pass


if __name__ == '__main__':
    main()
