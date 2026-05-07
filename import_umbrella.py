#!/usr/bin/env python3
# imports cisco umbrella top 1m csv into mongodb
# usage: python3 import_umbrella.py ~/bugbounty/top-1m.csv

import sys
import csv
from pymongo import MongoClient, ASCENDING

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "scannerdb"
COLLECTION = "umbrella"
CHUNK_SIZE = 10000

def main():
    if len(sys.argv) < 2:
        print("usage: python3 import_umbrella.py /path/to/top-1m.csv")
        sys.exit(1)

    csv_path = sys.argv[1]

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION]

    print(f"[*] dropping existing umbrella collection...")
    col.drop()

    print(f"[*] importing {csv_path}...")

    chunk = []
    total = 0

    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
                domain = row[1].strip().lower()
            except ValueError:
                continue

            chunk.append({"rank": rank, "domain": domain})
            total += 1

            if len(chunk) >= CHUNK_SIZE:
                col.insert_many(chunk)
                chunk = []
                print(f"[*] imported {total} domains...", end="\r")

    if chunk:
        col.insert_many(chunk)

    print(f"[+] done -- {total} domains imported")

    print("[*] creating index on domain field...")
    col.create_index([("domain", ASCENDING)], unique=True)
    col.create_index([("rank", ASCENDING)])
    print("[+] index created")

if __name__ == "__main__":
    main()
