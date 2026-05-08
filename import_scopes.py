#!/usr/bin/env python3
# downloads all h1 + bugcrowd scope data and imports into mongodb
# sources: bounty-targets-data (arkadiyt) + direct bugcrowd VDP scrape
# usage: python3 import_scopes.py

import json
import time
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse
from pymongo import MongoClient, ASCENDING

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"
COLLECTION = "scopes"

H1_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
BC_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"
BC_VDP_LIST_URL = "https://bugcrowd.com/engagements.json?category=vdp&sort_by=promoted&sort_direction=desc&page={page}"

H1_SKIP_TYPES = {
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER", "HARDWARE",
    "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "CIDR", "IP_ADDRESS",
}
BC_SKIP_TYPES = {"ios", "android", "executable", "other", "hardware", "source_code", "network"}
BC_VDP_KEEP_CATS = {"website", "api"}


def fetch_json(url):
    print(f"[*] fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
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


def extract_bc_vdp_asset(target):
    uri = (target.get("uri") or "").strip()
    name = (target.get("name") or "").strip()

    for val in [uri, name]:
        if not val:
            continue
        # wildcard subdomain only (*.example.com), no path component
        if val.startswith("*.") and "/" not in val:
            return val.lower()
        try:
            parsed = urlparse(val if "://" in val else "https://" + val)
            if parsed.netloc:
                return parsed.netloc.lower()
        except Exception:
            pass
    return ""


class _EndpointParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.endpoints = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("data-react-class") == "ResearcherEngagementBrief":
            try:
                self.endpoints = json.loads(a.get("data-api-endpoints", "{}"))
            except Exception:
                pass


def _fetch_bc_vdp_program_scope(brief_url):
    req = urllib.request.Request(
        f"https://bugcrowd.com{brief_url}",
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        html = r.read().decode()

    p = _EndpointParser()
    p.feed(html)
    if not p.endpoints:
        return []

    doc_path = p.endpoints.get("engagementBriefApi", {}).get("getBriefVersionDocument")
    if not doc_path:
        return []

    req2 = urllib.request.Request(
        f"https://bugcrowd.com{doc_path}.json",
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req2, timeout=20) as r:
        brief = json.loads(r.read())

    return brief.get("data", {}).get("scope", [])


def parse_h1(data):
    entries = []
    seen = set()
    for program in data:
        handle = program.get("handle", "")
        name = program.get("name", handle)
        url = program.get("url", f"https://hackerone.com/{handle}")
        platform = "hackerone" if program.get("offers_bounties") else "hackerone_vdp"
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


def parse_bc(data):
    entries = []
    seen = set()
    for program in data:
        name = program.get("name", "")
        url = program.get("url", "")
        platform = "bugcrowd" if program.get("max_payout") else "bugcrowd_vdp"
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


def scrape_bc_vdp():
    entries = []
    seen = set()
    page = 1
    total_programs = 0

    while True:
        data = fetch_json(BC_VDP_LIST_URL.format(page=page))
        engagements = data.get("engagements", [])
        if not engagements:
            break

        for eng in engagements:
            brief_url = eng.get("briefUrl", "")
            if not brief_url:
                continue
            name = eng.get("name", "")
            handle = brief_url.rstrip("/").split("/")[-1]
            prog_url = f"https://bugcrowd.com{brief_url}"

            try:
                scope_groups = _fetch_bc_vdp_program_scope(brief_url)
                total_programs += 1
                for group in scope_groups:
                    in_scope = group.get("inScope")
                    group_name = group.get("name", "").lower()
                    if in_scope is False:
                        continue
                    if in_scope is None and "out of scope" in group_name:
                        continue
                    for target in group.get("targets", []):
                        cat = (target.get("category") or "").lower()
                        if cat not in BC_VDP_KEEP_CATS:
                            continue
                        asset = extract_bc_vdp_asset(target)
                        if not asset or asset in seen:
                            continue
                        seen.add(asset)
                        entries.append({
                            "program": name,
                            "handle": handle,
                            "platform": "bugcrowd_vdp",
                            "url": prog_url,
                            "asset": asset.lower(),
                            "asset_type": cat,
                        })
                time.sleep(0.2)
            except Exception as e:
                print(f"[!] error fetching {handle}: {e}")

        meta = data.get("paginationMeta", {})
        total = meta.get("totalCount", 0)
        limit = meta.get("limit", 24)
        if page * limit >= total:
            break
        page += 1

    print(f"[+] {len(entries)} bugcrowd vdp scope entries from {total_programs} programs")
    return entries


def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION]

    h1_data = fetch_json(H1_URL)
    h1_entries = parse_h1(h1_data)
    h1_bounty = sum(1 for e in h1_entries if e["platform"] == "hackerone")
    h1_vdp = sum(1 for e in h1_entries if e["platform"] == "hackerone_vdp")
    print(f"[+] {len(h1_entries)} h1 scope entries ({h1_bounty} bounty, {h1_vdp} vdp) from {len(h1_data)} programs")

    bc_data = fetch_json(BC_URL)
    bc_entries = parse_bc(bc_data)
    print(f"[+] {len(bc_entries)} bugcrowd bounty scope entries from {len(bc_data)} programs")

    print("[*] scraping bugcrowd vdp programs (215 programs, ~2 min)...")
    bc_vdp_entries = scrape_bc_vdp()

    all_entries = h1_entries + bc_entries + bc_vdp_entries

    print("[*] dropping existing scopes collection...")
    col.drop()

    print(f"[*] inserting {len(all_entries)} scope entries...")
    if all_entries:
        col.insert_many(all_entries)

    col.create_index([("asset", ASCENDING)])
    col.create_index([("platform", ASCENDING)])
    col.create_index([("handle", ASCENDING)])

    print(f"[+] done -- {len(all_entries)} total scope entries")


if __name__ == "__main__":
    main()
    from tag_results import main as tag_main
    tag_main()
