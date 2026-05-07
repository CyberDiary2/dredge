#!/usr/bin/env python3
# runs stab against domains pulled from the dredge mongodb database
# usage:
#   python3 run_stab.py                         -- all domains in db
#   python3 run_stab.py --domain t-mobile.com   -- only domains matching filter

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"

_candidates = [
    "/root/stab/venv/bin/stab",
    "/home/guest/repos/stab/venv/bin/stab",
]
STAB_BIN = next((p for p in _candidates if os.path.exists(p)), "stab")

SECTIONS = [
    "https_responseForDomainName",
    "http_responseForDomainName",
    "https_responseForIP",
    "http_responseForIP",
]


def extract_domains(collection, domain_filter=None):
    domains = set()
    for doc in collection.find({}, {"_id": 0}):
        for section in SECTIONS:
            s = doc.get(section)
            if not s:
                continue
            items = s if isinstance(s, list) else [s]
            for item in items:
                d = item.get("domain", "").strip().lower().lstrip("*.")
                if not d:
                    continue
                if domain_filter is None or domain_filter.lower() in d:
                    domains.add(d)
    return sorted(domains)


def run_stab(domains, domain_label, output_dir, concurrency):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(domains))
        tmpfile = f.name

    try:
        cmd = [
            STAB_BIN, domain_label,
            "--no-enumerate",
            "--input", tmpfile,
            "--output", output_dir,
            "--concurrency", str(concurrency),
        ]
        print(f"[*] running stab on {len(domains)} domains (concurrency={concurrency})")
        subprocess.run(cmd, check=True)

        jsonl_files = sorted(Path(output_dir).glob("*_stab.jsonl"))
        if not jsonl_files:
            return []

        findings = []
        with open(jsonl_files[-1]) as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        return findings
    finally:
        os.unlink(tmpfile)


def main():
    parser = argparse.ArgumentParser(description="run stab on domains from dredge db")
    parser.add_argument("--domain", "-d", help="only check domains containing this string (e.g. t-mobile.com)")
    parser.add_argument("--concurrency", "-c", type=int, default=20, help="concurrent stab checks (default: 20)")
    args = parser.parse_args()

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db["sslchecker"]
    stab_col = db["stab_results"]

    print("[*] extracting domains from database...")
    domains = extract_domains(collection, args.domain)

    if not domains:
        print("[!] no domains found" + (f" matching '{args.domain}'" if args.domain else ""))
        sys.exit(1)

    print(f"[*] {len(domains)} unique domains to scan")
    preview = domains[:20]
    for d in preview:
        print(f"    {d}")
    if len(domains) > 20:
        print(f"    ... and {len(domains) - 20} more")

    domain_label = args.domain.replace("/", "_") if args.domain else "dredge_scan"

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = run_stab(domains, domain_label, tmpdir, args.concurrency)

    vuln = [f for f in findings if f.get("type") in ("cname_takeover", "s3_takeover", "ns_takeover")]

    print(f"\n[+] stab complete -- {len(vuln)} takeover candidate(s) out of {len(findings)} findings")

    if vuln:
        print("\n  takeover candidates:")
        for v in sorted(vuln, key=lambda x: x["subdomain"]):
            evidence = v.get("evidence") or v.get("ns_record") or v.get("cname") or "-"
            print(f"  [{v['type']}] {v['subdomain']} -- {v.get('service')} -- {evidence}")

        now = datetime.now(timezone.utc).isoformat()
        for finding in vuln:
            finding["scanned_at"] = now
            finding["filter"] = args.domain or "all"

        stab_col.insert_many(vuln)
        print(f"\n[+] inserted {len(vuln)} findings into stab_results collection")
    else:
        print("[*] no takeover candidates found")


if __name__ == "__main__":
    main()
