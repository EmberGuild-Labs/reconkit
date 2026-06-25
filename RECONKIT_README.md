# ReconKit

A domain intelligence tool that pulls full WHOIS registration data and every DNS record type for any domain — all in one clean report. Part of the [SentinelKit](https://github.com/EmberGuild-Labs/sentinelkit) ecosystem.

Live at: **[recon.proxnode.xyz](https://recon.proxnode.xyz)**

---

## Features

- Full WHOIS lookup — registrar, creation date, expiry date, name servers, registrant info (where not redacted)
- Complete DNS record dump — A, AAAA, MX, TXT, NS, CNAME, SOA, CAA
- Dangling subdomain detection on common prefixes (www, mail, ftp, dev, staging, api, etc.)
- SPF and DMARC record parsing from TXT records
- MX priority ranking display
- CAA record analysis — which CAs are authorized to issue certs for the domain
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
│   ├── index.html       # Domain input page
│   └── results.html     # Results breakdown page
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

App runs at `http://localhost:5000`.

### Deploy via ProxDeploy

1. Push to GitHub under EmberGuild-Labs
2. Open ProxDeploy at `proxnode.xyz`
3. Name: `reconkit`, Repo: `EmberGuild-Labs/reconkit`
4. Subdomain: `recon.proxnode.xyz`
5. Deploy

---

## How It Works

1. User submits a domain name
2. Flask runs a WHOIS query via `python-whois` and parses the structured response
3. `dnspython` fires queries for each record type (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA) against the system resolver
4. `subdomain.py` checks a wordlist of common subdomain prefixes for live A/CNAME records
5. TXT records are scanned for SPF (`v=spf1`) and DMARC (`v=DMARC1`) entries and parsed separately
6. Results are rendered in a structured, categorized report

---

## Use Cases

- Auditing your own domains (proxnode.xyz, subdomains) for misconfigurations
- Investigating suspicious domains before visiting them
- Checking whether SPF/DMARC are correctly configured on a domain
- Verifying DNS propagation after making record changes
- Finding forgotten or dangling subdomains

---

## Roadmap

- [ ] Historical WHOIS diff (detect recent ownership changes)
- [ ] Bulk domain input (paste a list, get reports for all)
- [ ] Export results as JSON or PDF
- [ ] Certificate transparency log check (find all subdomains via crt.sh)
- [ ] Reverse IP lookup (what else is hosted on the same IP)

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

## License

MIT © EmberGuild-Labs
