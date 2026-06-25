# ReconKit

A domain intelligence tool that pulls full WHOIS registration data and every DNS record type for any domain — all in one clean report. Part of the [SentinelKit](https://github.com/EmberGuild-Labs/sentinelkit) ecosystem.

Live at: **[recon.proxnode.xyz](https://recon.proxnode.xyz)**

---

## Features

- Full WHOIS lookup — registrar, creation date, expiry date, name servers, registrant info (where not redacted)
- Complete DNS record dump — A, AAAA, MX, TXT, NS, CNAME, SOA, CAA
- Dangling subdomain detection on common prefixes (www, mail, ftp, dev, staging, api, etc.)
- SPF record parsing from TXT records
- DMARC record lookup and parsing from `_dmarc.<domain>`
- MX priority ranking display
- CAA record analysis — which CAs are authorized to issue certs
- Response time displayed per DNS query

---

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | Python 3, Flask |
| WHOIS | `python-whois` |
| DNS lookups | `dnspython` |
| Frontend | Vanilla JS, HTML/CSS |
| Hosting | proxnode.xyz via ProxDeploy + Cloudflare Tunnel |

---

## Project Structure

```
reconkit/
├── app.py               # Flask app and routes
├── whois_lookup.py      # WHOIS fetching and parsing
├── dns_lookup.py        # DNS record fetching for all types
├── subdomain.py         # Dangling subdomain checker
├── static/
│   ├── style.css
│   └── main.js
├── templates/
│   └── index.html       # Domain input + results (single-page app)
├── requirements.txt
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/EmberGuild-Labs/reconkit
cd reconkit
pip install -r requirements.txt
```

### Run locally

```bash
python app.py
```

App runs at `http://localhost:5002`.

### Deploy via ProxDeploy

1. Push to GitHub under EmberGuild-Labs
2. Open ProxDeploy at `deploy.proxnode.xyz`
3. Name: `reconkit`, Repo: `EmberGuild-Labs/reconkit`
4. Type: Dynamic, Port: 5002
5. Subdomain: `recon.proxnode.xyz`
6. Deploy

---

## How It Works

1. User submits a domain name
2. Flask runs a WHOIS query via `python-whois` and parses the structured response
3. `dnspython` fires queries for each record type (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA) against the system resolver
4. `subdomain.py` checks a wordlist of common subdomain prefixes for live A/CNAME records and flags dangling CNAMEs
5. TXT records are scanned for SPF (`v=spf1`) entries; `_dmarc.<domain>` is queried separately for DMARC
6. Results are rendered in a structured, categorized report

---

## Use Cases

- Auditing your own domains for misconfigurations
- Investigating suspicious domains before visiting them
- Checking whether SPF/DMARC are correctly configured on a domain
- Verifying DNS propagation after making record changes
- Finding forgotten or dangling subdomains

---

## Part of SentinelKit

| Tool | URL | Purpose |
|---|---|---|
| **SentinelKit** | sentinelkit.proxnode.xyz | Hub |
| **ReconKit** | recon.proxnode.xyz | WHOIS + DNS |
| **ChainTrace** | trace.proxnode.xyz | Redirect tracing |
| **PhishLens** | phishlens.proxnode.xyz | Email header analysis |
| **TLSpy** | tlspy.proxnode.xyz | TLS inspection |

---

## Notes

- Uses port 5002 to avoid conflicting with ChainTrace (5000) and PhishLens (5001) on the same Pi
- Subdomain scanning checks 26 common prefixes — not a brute-force scan, runs fast
- WHOIS results vary by TLD; some registrars redact all registrant info behind privacy services
- DMARC is looked up separately at `_dmarc.<domain>` rather than relying on the main TXT records

---

## License

MIT
