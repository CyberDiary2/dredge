#!/usr/bin/env python3
# downloads all h1 + bugcrowd scope data and imports into mongodb
# source: bounty-targets-data (updated daily by arkadiyt)
# usage: python3 import_scopes.py

import json
import urllib.request
from urllib.parse import urlparse
from pymongo import MongoClient, ASCENDING

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"
COLLECTION = "scopes"

H1_URL     = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
H1_VDP_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_vdp_data.json"
BC_URL     = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"
BC_VDP_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_vdp_data.json"

H1_SKIP_TYPES = {
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER", "HARDWARE",
    "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "CIDR", "IP_ADDRESS",
}
BC_SKIP_TYPES = {"ios", "android", "executable", "other", "hardware", "source_code"}


def fetch_json(url):
    print(f"[*] fetching {url}")
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def extract_bc_asset(item):
    name = item.get("name", "").strip()
    target = item.get("target", "").strip()

    if "*" in name and "." in name:
        return name.rstrip("/")

    if target:
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc.lower()
            if "." in target and not target.startswith("http"):
                return target.rstrip("/").lower()
        except Exception:
            pass
    return ""


def parse_h1(data, platform="hackerone"):
    entries = []
    seen = set()
    for program in data:
        handle = program.get("handle", "")
        name = program.get("name", handle)
        url = program.get("url", f"https://hackerone.com/{handle}")
        for scope in program.get("targets", {}).get("in_scope", []):
            asset_type = scope.get("asset_type", "")
            if asset_type in H1_SKIP_TYPES:
                continue
            asset = scope.get("asset_identifier", "").strip().lower()
            if not asset or asset in seen:
                continue
            seen.add(asset)
            entries.append({
                "program": name,
                "handle": handle,
                "platform": platform,
                "url": url,
                "asset": asset,
                "asset_type": asset_type,
            })
    return entries


def parse_bc(data, platform="bugcrowd"):
    entries = []
    seen = set()
    for program in data:
        name = program.get("name", "")
        url = program.get("url", "")
        for scope in program.get("targets", {}).get("in_scope", []):
            asset_type = scope.get("type", "")
            if asset_type in BC_SKIP_TYPES:
                continue
            asset = extract_bc_asset(scope)
            if not asset or asset in seen:
                continue
            seen.add(asset)
            entries.append({
                "program": name,
                "handle": url.rstrip("/").split("/")[-1],
                "platform": platform,
                "url": url,
                "asset": asset.lower(),
                "asset_type": asset_type,
            })
    return entries


def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION]

    h1_data = fetch_json(H1_URL)
    h1_entries = parse_h1(h1_data, "hackerone")
    print(f"[+] {len(h1_entries)} h1 scope entries from {len(h1_data)} programs")

    h1_vdp_data = fetch_json(H1_VDP_URL)
    h1_vdp_entries = parse_h1(h1_vdp_data, "hackerone_vdp")
    print(f"[+] {len(h1_vdp_entries)} h1 vdp scope entries from {len(h1_vdp_data)} programs")

    bc_data = fetch_json(BC_URL)
    bc_entries = parse_bc(bc_data, "bugcrowd")
    print(f"[+] {len(bc_entries)} bugcrowd scope entries from {len(bc_data)} programs")

    bc_vdp_data = fetch_json(BC_VDP_URL)
    bc_vdp_entries = parse_bc(bc_vdp_data, "bugcrowd_vdp")
    print(f"[+] {len(bc_vdp_entries)} bugcrowd vdp scope entries from {len(bc_vdp_data)} programs")

    all_entries = h1_entries + h1_vdp_entries + bc_entries + bc_vdp_entries

    print("[*] dropping existing scopes collection...")
    col.drop()

    print(f"[*] inserting {len(all_entries)} scope entries...")
    if all_entries:
        col.insert_many(all_entries)

    col.create_index([("asset", ASCENDING)])
    col.create_index([("platform", ASCENDING)])
    col.create_index([("handle", ASCENDING)])

    print(f"[+] done -- {len(all_entries)} total scope entries (h1={len(h1_entries)}, h1_vdp={len(h1_vdp_entries)}, bc={len(bc_entries)}, bc_vdp={len(bc_vdp_entries)})")


if __name__ == "__main__":
    main()
    from tag_results import main as tag_main
    tag_main()
