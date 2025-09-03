#!/usr/bin/env python3
import requests
import csv
from datetime import datetime, timedelta
import time
import re
import gzip
import base64
from urllib.parse import urlparse
from collections import OrderedDict

# ---------- Config ----------
API_KEY = 'ba07db35-b8d3-45e0-bec1-0777195feb0c'
BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
HEADERS = {
    'User-Agent': 'NVD-API-Client/1.0',
    'apiKey': API_KEY,
}
KEYWORD = 'linux kernel'
RESULTS_PER_PAGE = 2000  # v2 allows up to 2000
CHUNK_DAYS = 120
OUTPUT_CSV = 'linux_data_nvd_8_31_ground.csv'

# Optional: map NVD sourceIdentifier GUIDs back to a vendor label
VENDOR_IDENTIFIERS = {
    'kernel.org': '416baaa9-dc9f-4396-8d5f-8c081fb06d67'
}

SHA_RE = re.compile(r'^[0-9a-f]{7,40}$', re.I)

# ---------- Helpers ----------
def isoformat_no_offset(dt):
    # NVD expects ISO UTC without timezone, with ms
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

def daterange_chunks(start_date, end_date, chunk_size_days=120):
    current_start = start_date
    while current_start < end_date:
        # pubEndDate is (effectively) inclusive; advance next start by 1 second to avoid duplicates
        current_end = min(current_start + timedelta(days=chunk_size_days), end_date)
        yield current_start, current_end
        current_start = current_end + timedelta(seconds=1)

def fetch_cves_page(start_date, end_date, start_index=0, keyword=None):
    params = {
        'resultsPerPage': RESULTS_PER_PAGE,
        'startIndex': start_index,
        'pubStartDate': start_date,
        'pubEndDate': end_date,
    }
    if keyword:
        params['keywordSearch'] = keyword

    r = requests.get(BASE_URL, headers=HEADERS, params=params, timeout=90)
    if r.status_code != 200:
        print(f"[ERROR] HTTP {r.status_code}")
        return None
    return r.json()

def get_vendor_key(source_identifier):
    for vendor, vendor_id in VENDOR_IDENTIFIERS.items():
        if source_identifier == vendor_id:
            return vendor
    return source_identifier or ""

# -------- Linux-kernel CPE filtering helpers --------
def _iter_linux_kernel_cpes_from_nodes(nodes):
    if not isinstance(nodes, list):
        return
    for node in nodes:
        for cm in (node.get("cpeMatch") or []):
            crit = cm.get("criteria") or cm.get("cpe23Uri")
            if not isinstance(crit, str):
                continue
            parts = crit.split(":")
            # cpe:2.3:<part>:<vendor>:<product>:<version>:...
            if len(parts) >= 6:
                product = (parts[4] or "").lower()
                if product == "linux_kernel":
                    yield crit
            else:
                if "linux_kernel" in crit.lower():
                    yield crit
        for child in (node.get("children") or []):
            yield from _iter_linux_kernel_cpes_from_nodes([child])

def extract_linux_kernel_criteria(vuln_item):
    cve = vuln_item.get("cve", {}) or {}
    configs = cve.get("configurations")
    linux_cpes = set()
    if isinstance(configs, list):
        for cfg in configs:
            nodes = cfg.get("nodes", []) or []
            for crit in _iter_linux_kernel_cpes_from_nodes(nodes):
                linux_cpes.add(crit)
    elif isinstance(configs, dict):
        nodes = configs.get("nodes", []) or []
        for crit in _iter_linux_kernel_cpes_from_nodes(nodes):
            linux_cpes.add(crit)
    return linux_cpes

# -------- Reference classification: Mainline vs Stable --------
def is_mainline_url(host: str, path: str) -> bool:
    """
    Classify mainline links:
      - GitHub: only torvalds/linux/...
      - git.kernel.org: /linus/<sha> (shortcut) OR any path under torvalds/linux.git
        (but not stable trees)
    """
    host = (host or "").lower()
    p = (path or "").strip("/").lower()

    # GitHub mainline must be torvalds/linux
    if host == "github.com":
        parts = p.split("/")
        return len(parts) >= 2 and parts[0] == "torvalds" and parts[1] == "linux"

    # git.kernel.org mainline
    if host == "git.kernel.org":
        # Reject stable/next/queue trees early
        if ("linux-stable.git" in p) or p.startswith("stable/") or "stable-rc" in p or "stable-queue" in p or "linux-next" in p:
            return False

        # Accept shortcut: /linus/<sha>[.patch|.diff]
        if p.startswith("linus/"):
            sha = p.split("/", 1)[1].split("/", 1)[0]
            sha = sha.split(".", 1)[0]  # strip .patch/.diff if present
            return bool(SHA_RE.match(sha))

        # Accept any path under torvalds/linux.git
        if "torvalds/linux.git" in p:
            return True

    return False

def is_stable_url(host: str, path: str) -> bool:
    """
    Classify 'stable' links.

    git.kernel.org
      • Shortcuts: /stable|stable-rc|stable-queue/(c|p)/<sha>
      • Any URL that points to repos under the stable namespace, including repo roots:
        linux-stable.git, linux.git (stable), stable-rc.git, stable-queue.git

    github.com
      • Repos named linux-stable, stable-rc, stable-queue
      • Or any repo whose name ends with -stable / -stable-rc / -stable-queue
    """
    host = (host or "").lower()
    p = (path or "").lower().strip("/")
    parts = p.split("/")

    if host == "git.kernel.org":
        # Short cgit forms: /stable|stable-rc|stable-queue/(c|p)/<sha>
        if len(parts) >= 3 and parts[0] in {"stable", "stable-rc", "stable-queue"} and parts[1] in {"c", "p"}:
            return True

        # Stable namespace repos (repo root or any subpage)
        if p.startswith("pub/scm/linux/kernel/git/stable/"):
            stable_repo_names = {
                "linux.git",
                "linux-stable.git",
                "stable-rc.git",
                "stable-queue.git",
            }
            if any(seg in stable_repo_names for seg in parts):
                return True

        # Common fallbacks seen in some paths
        if "linux-stable.git" in p or "/stable/linux.git" in p or "stable-rc.git" in p or "stable-queue.git" in p:
            return True

        return False

    if host == "github.com":
        # /<owner>/<repo>/...
        if len(parts) >= 2:
            repo = parts[1]
            if repo in {"linux-stable", "stable-rc", "stable-queue"}:
                return True
            if repo.endswith("-stable") or repo.endswith("-stable-rc") or repo.endswith("-stable-queue"):
                return True
        return False

    return False



def collect_mainline_and_stable_links(refs):
    mainline, stable = OrderedDict(), OrderedDict()
    for ref in refs or []:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        try:
            pr = urlparse(url)
        except Exception:
            continue
        host = pr.netloc.split(":")[0].lower()
        path = pr.path or ""
        if is_mainline_url(host, path):
            mainline[url] = True
        if is_stable_url(host, path):
            stable[url] = True
    # Return semicolon-joined strings, preserving first-seen order
    ml = "; ".join(mainline.keys()) if mainline else "N/A"
    st = "; ".join(stable.keys()) if stable else "N/A"
    return ml, st

# -------- CVSS v3 metrics extraction --------
def extract_cvssv3_metrics(cve_obj):
    """
    Prefer cvssMetricV31; fallback to cvssMetricV30.
    Returns dict with requested fields or 'N/A' if unavailable.
    """
    metrics = (cve_obj.get("metrics") or {})
    entries = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if not entries:
        return {
            "baseScore": "N/A",
            "baseSeverity": "N/A",
            "attackVector": "N/A",
            "attackComplexity": "N/A",
            "confidentialityImpact": "N/A",
            "integrityImpact": "N/A",
            "availabilityImpact": "N/A",
            "exploitabilityScore": "N/A",
        }
    m = entries[0]  # take the first scoring vector
    data = m.get("cvssData") or {}
    return {
        "baseScore": str(data.get("baseScore", "N/A")),
        "baseSeverity": data.get("baseSeverity", "N/A"),
        "attackVector": data.get("attackVector", "N/A"),
        "attackComplexity": data.get("attackComplexity", "N/A"),
        "confidentialityImpact": data.get("confidentialityImpact", "N/A"),
        "integrityImpact": data.get("integrityImpact", "N/A"),
        "availabilityImpact": data.get("availabilityImpact", "N/A"),
        "exploitabilityScore": str(m.get("exploitabilityScore", "N/A")),
    }

# -------- Description compression --------
def compress_text_gz_b64(s: str) -> str:
    if not s:
        return ""
    raw = s.encode("utf-8")
    gz = gzip.compress(raw)
    b64 = base64.b64encode(gz).decode("ascii")
    return b64

# ---------- Main ----------
if __name__ == "__main__":
    start = datetime(2015, 1, 1)
    end = datetime.utcnow()

    # De-duplicate CVEs by ID as we stream chunks
    seen_ids = set()
    kept_rows = 0

    fieldnames = [
        "CVE ID",
        "CVE URL",
        "Vendor Name",
        "Published Date",
        "Last Modified Date",
        "Vulnerability Status",
        "CWE IDs",
        "Description (gz+b64)",
        "References",
        "Mainline Links",
        "Stable Links",
        # CVSS v3
        "CVSS Base Score",
        "CVSS Base Severity",
        "CVSS Attack Vector",
        "CVSS Attack Complexity",
        "CVSS Confidentiality Impact",
        "CVSS Integrity Impact",
        "CVSS Availability Impact",
        "CVSS Exploitability Score",
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for chunk_start, chunk_end in daterange_chunks(start, end, CHUNK_DAYS):
            print(f"Fetching CVEs from {chunk_start} to {chunk_end}")
            start_idx = 0
            total_results = None

            while True:
                data = fetch_cves_page(
                    start_date=isoformat_no_offset(chunk_start),
                    end_date=isoformat_no_offset(chunk_end),
                    start_index=start_idx,
                    keyword=KEYWORD
                )
                if data is None:
                    print("[WARN] Skipping this page due to fetch error.")
                    break

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    print(f"Total results in this chunk: {total_results}")

                vulnerabilities = data.get("vulnerabilities", []) or []
                for item in vulnerabilities:
                    cve = item.get("cve", {}) or {}
                    cve_id = cve.get("id")
                    if not cve_id or cve_id in seen_ids:
                        continue

                    # Filter: keep if linux_kernel CPEs present OR CNA is kernel.org
                    linux_cpes = extract_linux_kernel_criteria(item)
                    source_identifier = cve.get("sourceIdentifier")
                    vendor_name = get_vendor_key(source_identifier)
                    keep = bool(linux_cpes) or (vendor_name == "kernel.org")
                    if not keep:
                        continue

                    seen_ids.add(cve_id)

                    # Basics
                    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    published_date = cve.get("published", "")
                    modified_date = cve.get("lastModified", "")
                    vuln_status = cve.get("vulnStatus", "")

                    # Description (NVD typically has a list; take English if present)
                    desc_list = (cve.get("descriptions") or [])
                    description = ""
                    for d in desc_list:
                        if d.get("lang") == "en" and d.get("value"):
                            description = d["value"]
                            break
                    if not description and desc_list:
                        description = desc_list[0].get("value", "") or ""

                    desc_compact = compress_text_gz_b64(description)

                    # CWE IDs
                    cwe_ids = []
                    for weakness in cve.get("weaknesses", []) or []:
                        for d in weakness.get("description", []) or []:
                            val = d.get("value")
                            if val:
                                cwe_ids.append(val)
                    cwe_ids_str = "; ".join(OrderedDict((x, None) for x in cwe_ids).keys()) if cwe_ids else "N/A"

                    # References (all)
                    references = [r.get("url", "") for r in (cve.get("references") or []) if r.get("url")]
                    references_str = "; ".join(references) if references else "N/A"

                    # Classify into Mainline vs Stable
                    mainline_links, stable_links = collect_mainline_and_stable_links(cve.get("references") or [])

                    # CVSS v3 metrics
                    cvss = extract_cvssv3_metrics(cve)

                    writer.writerow({
                        "CVE ID": cve_id,
                        "CVE URL": url,
                        "Vendor Name": vendor_name,
                        "Published Date": published_date,
                        "Last Modified Date": modified_date,
                        "Vulnerability Status": vuln_status,
                        "CWE IDs": cwe_ids_str,
                        "Description (gz+b64)": desc_compact,
                        "References": references_str,
                        "Mainline Links": mainline_links,
                        "Stable Links": stable_links,
                        "CVSS Base Score": cvss["baseScore"],
                        "CVSS Base Severity": cvss["baseSeverity"],
                        "CVSS Attack Vector": cvss["attackVector"],
                        "CVSS Attack Complexity": cvss["attackComplexity"],
                        "CVSS Confidentiality Impact": cvss["confidentialityImpact"],
                        "CVSS Integrity Impact": cvss["integrityImpact"],
                        "CVSS Availability Impact": cvss["availabilityImpact"],
                        "CVSS Exploitability Score": cvss["exploitabilityScore"],
                    })
                    kept_rows += 1

                start_idx += RESULTS_PER_PAGE
                if start_idx >= (total_results or 0):
                    break

            print(f"Rows kept so far: {kept_rows}")
            time.sleep(7)  # be nice to the API

    print(f"Done. Wrote {kept_rows} rows to {OUTPUT_CSV}")
