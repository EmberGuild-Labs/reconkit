import dns.resolver

COMMON_PREFIXES = [
    "www", "mail", "ftp", "dev", "staging", "api", "app",
    "admin", "blog", "shop", "store", "cdn", "media",
    "test", "beta", "demo", "portal", "vpn", "remote",
    "webmail", "smtp", "imap", "pop", "ns1", "ns2",
]


def check_subdomains(domain):
    """Check common subdomain prefixes for live A/CNAME records."""
    results = []

    for prefix in COMMON_PREFIXES:
        subdomain = f"{prefix}.{domain}"
        record = _resolve(subdomain)
        if record:
            results.append({
                "subdomain": subdomain,
                "type": record["type"],
                "value": record["value"],
                "is_dangling": record["is_dangling"],
            })

    return results


def _resolve(subdomain):
    """Try to resolve a subdomain, checking for dangling CNAMEs."""
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        cname_target = str(answers[0].target)
        try:
            dns.resolver.resolve(cname_target, "A")
            return {"type": "CNAME", "value": cname_target, "is_dangling": False}
        except Exception:
            return {"type": "CNAME", "value": cname_target, "is_dangling": True}
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(subdomain, "A")
        return {"type": "A", "value": answers[0].to_text(), "is_dangling": False}
    except Exception:
        pass

    return None
