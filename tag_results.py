#!/usr/bin/env python3
# matches dredge scan results against bug bounty scopes
# updates each document with in_scope_program, in_scope_platform, in_scope_url fields
# usage: python3 tag_results.py

import sys
from collections import defaultdict
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"

SECTIONS = [
    "https_responseForDomainName",
    "http_responseForDomainName",
    "https_responseForIP",
    "http_responseForIP",
]


def extract_domain(doc):
    for section in SECTIONS:
        s = doc.get(section)
        if not s:
            continue
        items = s if isinstance(s, list) else [s]
        for item in items:
            d = item.get("domain", "").strip().lower().lstrip("*.")
            if d:
                return d
    return None


def domain_matches(domain, asset):
    asset = asset.lower().lstrip("*.").rstrip("/")
    domain = domain.lower()
    return domain == asset or domain.endswith("." + asset)


def build_scope_index(scopes_col):
    index = defaultdict(list)
    skip_types = {"cidr", "ip_address", "ip", "android", "ios", "executable", "other", "hardware", "source_code", "google_play_app_id", "apple_store_app_id", "downloadable_executables"}
    for scope in scopes_col.find({}, {"_id": 0}):
        asset = scope.get("asset", "").lower().strip()
        if not asset or "." not in asset:
            continue
        if scope.get("asset_type", "").lower() in skip_types:
            continue
        base = ".".join(asset.lstrip("*.").split(".")[-2:])
        index[base].append(scope)
    return index


def find_match(domain, scope_index):
    if not domain or "." not in domain:
        return None, None, None
    parts = domain.split(".")
    base = ".".join(parts[-2:])
    for scope in scope_index.get(base, []):
        if domain_matches(domain, scope.get("asset", "")):
            return scope.get("program"), scope.get("platform"), scope.get("url")
    return None, None, None


def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db["sslchecker"]
    scopes_col = db["scopes"]

    scope_count = scopes_col.count_documents({})
    if scope_count == 0:
        print("[!] no scopes found -- run import_scopes.py first")
        sys.exit(1)

    print(f"[*] {scope_count} scope entries loaded")
    print("[*] building scope index...")
    scope_index = build_scope_index(scopes_col)
    print(f"[*] {sum(len(v) for v in scope_index.values())} domain scope entries indexed")

    total = collection.count_documents({})
    print(f"[*] tagging {total} scan results...")

    tagged = 0
    in_scope = 0

    for doc in collection.find({}, {"_id": 1, **{s: 1 for s in SECTIONS}}):
        domain = extract_domain(doc)
        program, platform, prog_url = find_match(domain, scope_index)

        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "in_scope_program": program,
                "in_scope_platform": platform,
                "in_scope_url": prog_url,
            }}
        )
        tagged += 1
        if program:
            in_scope += 1

        if tagged % 500 == 0:
            print(f"[*] {tagged}/{total} tagged, {in_scope} in scope...", end="\r")

    print(f"\n[+] done -- {tagged} records tagged, {in_scope} in scope")


if __name__ == "__main__":
    main()
