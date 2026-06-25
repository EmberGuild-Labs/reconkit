import time
import dns.resolver


RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


def lookup_dns(domain):
    """Query all DNS record types for a domain."""
    results = {}
    spf = None
    dmarc = None

    for rtype in RECORD_TYPES:
        start = time.time()
        try:
            answers = dns.resolver.resolve(domain, rtype)
            elapsed_ms = round((time.time() - start) * 1000)
            records = []

            for rdata in answers:
                record = {"value": rdata.to_text()}

                if rtype == "MX":
                    record["priority"] = rdata.preference
                    record["exchange"] = str(rdata.exchange)
                elif rtype == "SOA":
                    record["mname"] = str(rdata.mname)
                    record["rname"] = str(rdata.rname)
                    record["serial"] = rdata.serial
                    record["refresh"] = rdata.refresh
                    record["retry"] = rdata.retry
                    record["expire"] = rdata.expire
                    record["minimum"] = rdata.minimum
                elif rtype == "CAA":
                    record["flags"] = rdata.flags
                    record["tag"] = rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag)
                    record["issuer"] = rdata.value

                records.append(record)

            if rtype == "MX":
                records.sort(key=lambda r: r.get("priority", 0))

            results[rtype] = {
                "records": records,
                "count": len(records),
                "response_time_ms": elapsed_ms,
            }

            if rtype == "TXT":
                for rec in records:
                    txt_val = rec["value"].strip('"')
                    if txt_val.startswith("v=spf1"):
                        spf = txt_val
        except dns.resolver.NoAnswer:
            results[rtype] = {"records": [], "count": 0, "response_time_ms": round((time.time() - start) * 1000)}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"records": [], "count": 0, "response_time_ms": round((time.time() - start) * 1000), "error": "Domain does not exist"}
        except dns.resolver.NoNameservers:
            results[rtype] = {"records": [], "count": 0, "response_time_ms": round((time.time() - start) * 1000), "error": "No nameservers available"}
        except Exception:
            results[rtype] = {"records": [], "count": 0, "response_time_ms": round((time.time() - start) * 1000)}

    dmarc = _lookup_dmarc(domain)

    return {
        "records": results,
        "spf": _parse_spf(spf) if spf else None,
        "dmarc": dmarc,
    }


def _lookup_dmarc(domain):
    """Look up the DMARC record at _dmarc.<domain>."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                return _parse_dmarc(txt)
    except Exception:
        pass
    return None


def _parse_spf(raw):
    """Parse an SPF record into components."""
    parts = raw.split()
    mechanisms = []
    for part in parts[1:]:
        mechanisms.append(part)
    return {
        "raw": raw,
        "mechanisms": mechanisms,
    }


def _parse_dmarc(raw):
    """Parse a DMARC record into components."""
    result = {"raw": raw}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "p":
                result["policy"] = val
            elif key == "sp":
                result["subdomain_policy"] = val
            elif key == "rua":
                result["aggregate_reports"] = val
            elif key == "ruf":
                result["forensic_reports"] = val
            elif key == "pct":
                result["percentage"] = val
            elif key == "adkim":
                result["dkim_alignment"] = "strict" if val == "s" else "relaxed"
            elif key == "aspf":
                result["spf_alignment"] = "strict" if val == "s" else "relaxed"
    return result
