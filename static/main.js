const form = document.getElementById("lookup-form");
const domainInput = document.getElementById("domain-input");
const lookupBtn = document.getElementById("lookup-btn");
const loading = document.getElementById("loading");
const errorMsg = document.getElementById("error-msg");
const results = document.getElementById("results");

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = domainInput.value.trim();
    if (!domain) return;

    loading.classList.remove("hidden");
    results.classList.add("hidden");
    errorMsg.classList.add("hidden");
    lookupBtn.disabled = true;

    try {
        const resp = await fetch("/lookup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain }),
        });

        const data = await resp.json();

        if (!resp.ok) {
            showError(data.error || "Something went wrong.");
            return;
        }

        renderResults(data);
    } catch {
        showError("Failed to connect to the server.");
    } finally {
        loading.classList.add("hidden");
        lookupBtn.disabled = false;
    }
});

function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.classList.remove("hidden");
}

function esc(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.textContent = String(str);
    return div.innerHTML;
}

function renderResults(data) {
    renderWhois(data.whois);
    renderDNS(data.dns);
    renderSPF(data.dns.spf);
    renderDMARC(data.dns.dmarc);
    renderSubdomains(data.subdomains);
    results.classList.remove("hidden");
}

function renderWhois(w) {
    const el = document.getElementById("whois-display");
    if (w.error) {
        el.innerHTML = `<div class="no-results">WHOIS error: ${esc(w.error)}</div>`;
        return;
    }

    const fields = [
        ["Domain", w.domain_name],
        ["Registrar", w.registrar],
        ["Created", w.creation_date],
        ["Expires", w.expiration_date],
        ["Updated", w.updated_date],
        ["Registrant", w.registrant],
        ["Country", w.country],
        ["DNSSEC", w.dnssec],
        ["Name Servers", (w.name_servers || []).join(", ")],
        ["Status", (w.status || []).join("\n")],
        ["Lookup Time", w.response_time_ms + "ms"],
    ];

    const rows = fields
        .filter(([, v]) => v)
        .map(([k, v]) => `<div class="info-row"><div class="info-key">${esc(k)}</div><div class="info-val">${esc(v)}</div></div>`)
        .join("");

    el.innerHTML = `<div class="info-table">${rows}</div>`;
}

function renderDNS(dns) {
    const el = document.getElementById("dns-display");
    const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"];
    let html = "";

    for (const type of types) {
        const data = dns.records[type];
        if (!data) continue;

        const count = data.count || 0;
        const time = data.response_time_ms || 0;
        const id = `dns-${type}`;

        let recordsHTML = "";
        if (count > 0) {
            recordsHTML = data.records.map((r) => {
                if (type === "MX") {
                    return `<div class="dns-record"><span class="mx-priority">${r.priority}</span>${esc(r.exchange)}</div>`;
                }
                let val = r.value;
                let tags = "";
                if (type === "TXT") {
                    const stripped = val.replace(/^"|"$/g, "");
                    if (stripped.startsWith("v=spf1")) tags = '<span class="tag tag-spf">SPF</span>';
                }
                return `<div class="dns-record">${tags}${esc(val)}</div>`;
            }).join("");
        } else {
            recordsHTML = '<div class="dns-record" style="color:var(--text-muted)">No records</div>';
        }

        html += `
            <div class="dns-type-card">
                <div class="dns-type-header" onclick="document.getElementById('${id}').classList.toggle('hidden')">
                    <span class="dns-type-name">${type}</span>
                    <div class="dns-type-meta">
                        <span class="dns-type-count">${count} record${count !== 1 ? "s" : ""}</span>
                        <span>${time}ms</span>
                    </div>
                </div>
                <div id="${id}" class="dns-records hidden">${recordsHTML}</div>
            </div>
        `;
    }

    el.innerHTML = html;
}

function renderSPF(spf) {
    const section = document.getElementById("spf-section");
    const el = document.getElementById("spf-display");

    if (!spf) {
        section.classList.add("hidden");
        return;
    }
    section.classList.remove("hidden");

    let mechHTML = spf.mechanisms.map((m) => `<div class="dns-record">${esc(m)}</div>`).join("");

    el.innerHTML = `
        <div class="policy-card">
            <div class="policy-raw">${esc(spf.raw)}</div>
            <div class="dns-records">${mechHTML}</div>
        </div>
    `;
}

function renderDMARC(dmarc) {
    const section = document.getElementById("dmarc-section");
    const el = document.getElementById("dmarc-display");

    if (!dmarc) {
        section.classList.add("hidden");
        return;
    }
    section.classList.remove("hidden");

    const fields = [
        ["Policy", dmarc.policy],
        ["Subdomain Policy", dmarc.subdomain_policy],
        ["DKIM Alignment", dmarc.dkim_alignment],
        ["SPF Alignment", dmarc.spf_alignment],
        ["Percentage", dmarc.percentage],
        ["Aggregate Reports", dmarc.aggregate_reports],
        ["Forensic Reports", dmarc.forensic_reports],
    ];

    const rows = fields
        .filter(([, v]) => v)
        .map(([k, v]) => `<div class="info-row"><div class="info-key">${esc(k)}</div><div class="info-val">${esc(v)}</div></div>`)
        .join("");

    el.innerHTML = `
        <div class="policy-card">
            <div class="policy-raw">${esc(dmarc.raw)}</div>
            ${rows ? `<div class="info-table policy-fields">${rows}</div>` : ""}
        </div>
    `;
}

function renderSubdomains(subs) {
    const el = document.getElementById("sub-display");

    if (!subs || subs.length === 0) {
        el.innerHTML = '<div class="no-results">No common subdomains found</div>';
        return;
    }

    el.innerHTML = subs.map((s) => `
        <div class="sub-card">
            <span class="sub-name">${esc(s.subdomain)}</span>
            <span class="sub-type">${esc(s.type)}</span>
            <span class="sub-value">${esc(s.value)}</span>
            ${s.is_dangling ? '<span class="tag-dangling">DANGLING</span>' : ""}
        </div>
    `).join("");
}
