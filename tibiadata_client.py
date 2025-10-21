#!/usr/bin/env python3
"""
Lightweight Tibiadata helper for Python.

- Prefers offline cache under New-folder--2-/cache/
- Can optionally fetch live JSON if TIBIADATA_ONLINE=1 is set (uses urllib)

Cache layout:
  New-folder--2-/cache/worlds.json
  New-folder--2-/cache/worlds/<WorldName>.json
"""
import os
import json
import urllib.request
import urllib.error

API_BASE = os.environ.get('TIBIADATA_API_BASE', 'https://api.tibiadata.com/v4')


def _cache_dir():
    return os.path.join(os.path.dirname(__file__), 'New-folder--2-', 'cache')


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _fetch_json(url: str):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        raise RuntimeError(f"tibiadata fetch failed: {e}")


def _save_cache(path: str, data):
    _ensure_dir(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _load_cache(path: str):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def get_worlds(allow_online: bool = False):
    cache_path = os.path.join(_cache_dir(), 'worlds.json')
    data = _load_cache(cache_path)
    if data is not None or not allow_online:
        return data
    # fetch live
    url = f"{API_BASE}/worlds.json"
    data = _fetch_json(url)
    _save_cache(cache_path, data)
    return data


def get_world_info(world_name: str, allow_online: bool = False):
    safe_name = world_name.strip().replace('/', '_')
    cache_path = os.path.join(_cache_dir(), 'worlds', f"{safe_name}.json")
    data = _load_cache(cache_path)
    if data is not None or not allow_online:
        return data
    url = f"{API_BASE}/world/{urllib.parse.quote(world_name)}.json"
    data = _fetch_json(url)
    _save_cache(cache_path, data)
    return data


def derive_service_from_ports(sport: int, dport: int):
    if 7171 in (sport, dport):
        return 'login'
    if 7172 in (sport, dport):
        return 'game'
    return None
