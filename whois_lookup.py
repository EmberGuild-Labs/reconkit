import whois
import time


def lookup_whois(domain):
    """Fetch and parse WHOIS data for a domain."""
    try:
        start = time.time()
        w = whois.whois(domain)
        elapsed_ms = round((time.time() - start) * 1000)
    except Exception as e:
        return {"error": str(e), "response_time_ms": 0}

    def first(val):
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def fmt_date(val):
        if not val:
            return None
        d = first(val) if isinstance(val, list) else val
        if hasattr(d, "isoformat"):
            return d.isoformat()
        return str(d)

    return {
        "domain_name": first(w.domain_name) if w.domain_name else domain,
        "registrar": w.registrar,
        "creation_date": fmt_date(w.creation_date),
        "expiration_date": fmt_date(w.expiration_date),
        "updated_date": fmt_date(w.updated_date),
        "name_servers": sorted(set(ns.lower() for ns in w.name_servers)) if w.name_servers else [],
        "status": w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
        "registrant": w.get("org") or w.get("name"),
        "country": w.get("country"),
        "dnssec": w.get("dnssec"),
        "response_time_ms": elapsed_ms,
        "error": None,
    }
