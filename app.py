from flask import Flask, render_template, request, jsonify
from whois_lookup import lookup_whois
from dns_lookup import lookup_dns
from subdomain import check_subdomains
import re

app = Flask(__name__)

DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.get_json()
    domain = data.get("domain", "").strip().lower() if data else ""

    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]

    if not domain or not DOMAIN_RE.match(domain):
        return jsonify({"error": "Invalid domain name"}), 400

    whois_data = lookup_whois(domain)
    dns_data = lookup_dns(domain)
    subdomains = check_subdomains(domain)

    return jsonify({
        "domain": domain,
        "whois": whois_data,
        "dns": dns_data,
        "subdomains": subdomains,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
