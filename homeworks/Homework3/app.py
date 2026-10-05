"""Security Recon Assistant: a LangGraph agent for Homework 3.

The agent answers security-research questions using a mix of built-in and
custom LangChain tools, and executes Python code only after a human approves it.

Configuration is read from environment variables (never hard-coded):
    GOOGLE_API_KEY  -- Gemini API key
    GOOGLE_MODEL    -- Gemini model name, e.g. ``gemini-flash-lite-latest``
"""

import json
import re

import dns.exception
import dns.resolver
import httpx
from langchain_community.tools import ArxivQueryRun, DuckDuckGoSearchRun
from langchain_core.tools import tool
from langchain_experimental.tools import PythonREPLTool

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


# ---------------------------------------------------------------------------
# Custom tools
# ---------------------------------------------------------------------------

@tool
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """Look up DNS records for a domain name.

    Use this for questions about a domain's IP addresses, mail servers (MX),
    name servers (NS), TXT records such as SPF/DMARC, or CAA records.
    record_type must be one of: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA.
    Returns a JSON object with the records found, or an error message.
    """
    record_type = record_type.strip().upper()
    if record_type not in DNS_RECORD_TYPES:
        return json.dumps({"error": f"Unsupported record type {record_type!r}. "
                                    f"Use one of {', '.join(DNS_RECORD_TYPES)}."})
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(domain.strip().rstrip("."), record_type)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return json.dumps({"domain": domain, "type": record_type, "records": []})
    except dns.exception.DNSException as exc:
        return json.dumps({"error": f"DNS lookup failed: {exc}"})
    return json.dumps({"domain": domain, "type": record_type,
                       "records": [rdata.to_text() for rdata in answer]})


@tool
def cve_lookup(cve_id: str) -> str:
    """Look up a CVE in the NIST National Vulnerability Database (NVD).

    Use this whenever the user mentions a specific CVE identifier such as
    CVE-2021-44228. Returns a JSON object with the description, CVSS base
    score and severity, publication date, and a few reference links.
    """
    cve_id = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(cve_id):
        return json.dumps({"error": f"{cve_id!r} is not a valid CVE ID (expected CVE-YYYY-NNNN)."})
    try:
        response = httpx.get(NVD_API_URL, params={"cveId": cve_id}, timeout=20,
                             follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        return json.dumps({"error": f"NVD request failed: {exc}"})

    vulns = response.json().get("vulnerabilities", [])
    if not vulns:
        return json.dumps({"error": f"{cve_id} was not found in the NVD."})
    cve = vulns[0]["cve"]

    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = severity = vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            vector = data.get("vectorString")
            break

    return json.dumps({
        "id": cve_id,
        "published": cve.get("published"),
        "description": description,
        "cvss_base_score": score,
        "severity": severity,
        "cvss_vector": vector,
        "references": [ref["url"] for ref in cve.get("references", [])[:5]],
    })


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

python_repl = PythonREPLTool()

TOOLS = [
    DuckDuckGoSearchRun(),  # built-in: web search, no API key needed
    ArxivQueryRun(),        # built-in: academic paper search
    dns_lookup,             # custom
    cve_lookup,             # custom
    python_repl,            # required: runs code, gated behind human approval
]

# Tools that can change the local system; every call needs explicit approval.
DANGEROUS_TOOLS = {python_repl.name}


def main():
    """Entry point for the interactive agent (implemented in later commits)."""
    print("Security Recon Assistant -- tools loaded:")
    for t in TOOLS:
        print(f"  {t.name}")


if __name__ == "__main__":
    main()
