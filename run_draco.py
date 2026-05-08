"""
Run draco cloud asset scan for a domain and store results in MongoDB.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"

DRACO_BINS = [
    "/root/draco/venv/bin/draco",
    os.path.expanduser("~/repos/draco/venv/bin/draco"),
]


def find_draco():
    for path in DRACO_BINS:
        if os.path.isfile(path):
            return path
    return shutil.which("draco")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, help="target domain")
    parser.add_argument("--no-intel", action="store_true", help="skip passive intel (crt.sh, github, shodan)")
    args = parser.parse_args()

    domain = args.domain.strip().lower().lstrip("*.").rstrip(".")

    draco_bin = find_draco()
    if not draco_bin:
        print("draco not found -- install at ~/repos/draco", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [draco_bin, "scan", domain, "--output", tmpdir]
        if args.no_intel:
            cmd.append("--no-intel")
        print(f"running draco: {' '.join(cmd)}", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.stdout:
            print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(result.returncode)

        jsonl_files = list(Path(tmpdir).glob("*.jsonl"))
        if not jsonl_files:
            print("draco produced no jsonl output")
            return

        findings = []
        for jf in jsonl_files:
            with open(jf) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

    client = MongoClient(MONGO_URI)
    col = client[DB_NAME]["draco_results"]
    ts = datetime.now(timezone.utc).isoformat()

    for finding in findings:
        finding["target_domain"] = domain
        finding["scanned_at"] = ts
        key = finding.get("url") or finding.get("name") or finding.get("hostname") or finding.get("fqdn", "")
        col.update_one(
            {"type": finding["type"], "target_domain": domain, "_key": key},
            {"$set": finding, "$setOnInsert": {"_key": key}},
            upsert=True
        )

    print(f"stored {len(findings)} findings for {domain}")


if __name__ == "__main__":
    main()
