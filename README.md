# scanner

a homebrew shodan-style scanner for bug bounty recon. takes a list of IP ranges, finds open HTTPS ports with masscan, pulls TLS certificates to extract domain names, fingerprints HTTP/HTTPS responses, and stores everything in MongoDB with a searchable web dashboard.

## how it works

```
ips.txt (IP ranges / CIDRs)
    |
    v
masscan (finds open ports: 443, 8443, 4443, 8080, 8888, 9443)
    |
    v
scanner.py (pulls TLS cert from each live IP, extracts domain name,
            makes HTTP + HTTPS requests, grabs title / body / headers)
    |
    v
MongoDB (stores all results)
    |
    v
server.py (Flask dashboard at http://127.0.0.1:5000)
```

## requirements

**system packages:**
```bash
sudo apt install masscan mongodb-org
```

**python packages:**
```bash
pip install aiohttp beautifulsoup4 pyopenssl pymongo flask --break-system-packages
```

## setup

**1. start MongoDB:**
```bash
sudo systemctl start mongod
```

or if systemd isn't available:
```bash
sudo mkdir -p /var/lib/mongodb
sudo mongod --fork --logpath /var/log/mongod.log --dbpath /var/lib/mongodb
```

**2. start the dashboard:**
```bash
python server.py
```

open `http://127.0.0.1:5000` in your browser.

**3. add your IP ranges:**
```bash
cp ~/bugbounty/targets/t-mobile/ip-blocks.txt ips.txt
```

one IP or CIDR per line:
```
172.56.248.0/21
208.54.0.0/17
10.0.0.1
```

**4. run the scanner:**
```bash
python scanner.py
```

domains print to the terminal live and are saved to `discovered-domains.txt` as they are found.

## dashboard

open `http://127.0.0.1:5000` -- search by:

| field | example | finds |
|---|---|---|
| domain | t-mobile.com | all records matching that domain |
| IP | 172.56.248.1 | all records for that IP |
| port | 8443 | all hosts with that port open |
| page title | login | pages with that word in the title |
| page content | admin panel | pages with that text in the body |
| response header | X-Powered-By | hosts exposing that header |

## output files

| file | contents |
|---|---|
| `ips.txt` | input IP ranges |
| `masscanResults.txt` | raw masscan output |
| `discovered-domains.txt` | all unique domain names found via TLS certs |

## configuration

edit the `SSLChecker()` call at the bottom of `scanner.py`:

```python
ssl_checker = SSLChecker(
    ssl_ports=[443, 8443, 4443, 8080, 8888, 9443],  # ports to scan
    masscan_rate=10000,                               # packets per second
    timeout=3,                                        # seconds per connection
    chunkSize=2000,                                   # IPs processed per batch
    semaphore_limit=70,                               # max concurrent connections
)
```

**masscan rate:** 10000 is safe for a VPS. lower it on a home connection to avoid dropping packets. 1000-5000 is reasonable at home.

## get IP ranges from BGP

pull T-Mobile IP blocks from RADB:
```bash
whois -h whois.radb.net -- '-i origin AS21928' | grep ^route: | awk '{print $2}' | sort -u > ips.txt
```

pull from multiple ASNs:
```bash
for asn in AS21928 AS13067 AS40157; do
    whois -h whois.radb.net -- "-i origin $asn" | grep ^route: | awk '{print $2}'
done | sort -u > ips.txt
```

## tips

- run `server.py` before `scanner.py` so results are inserted as they come in
- watch domains live: `tail -f discovered-domains.txt`
- grep results for a specific company: `grep -i 't-mobile' discovered-domains.txt`
- clear the database between targets using the "clear db" button in the dashboard
- run on a VPS for higher masscan rates and faster scanning
