# NVD CVE API v2.0

Official documentation: <https://nvd.nist.gov/developers/vulnerabilities>. Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`. Confirm parameters against the live documentation before expanding these examples; the API can change.

Compatibility checked on 2026-10-13: a public `cveId=CVE-2024-3094` GET returned one matching record. The broader filters below follow the NVD documentation but were not live-tested here.

## Bounded requests

```bash
curl -fsS --max-time 20 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094'
curl -fsS --max-time 20 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=path+traversal&resultsPerPage=10&startIndex=0&noRejected'
```

Use `cveId` for one ID. For broader results, page with `startIndex` and `resultsPerPage`, observe `totalResults`, and stop at a task-relevant bound. NVD also documents filters such as `cweId`, `hasKev`, `pubStartDate`/`pubEndDate`, and `lastModStartDate`/`lastModEndDate`. URL-encode user-supplied values. Keep date windows within documented limits. Respect rate limits and any `Retry-After`; do not loop unchanged failed calls. Supply an API key privately when needed, never in a committed URL or transcript.

## Record checks

Inspect `vulnerabilities[].cve.id`, `vulnStatus`, `published`, `lastModified`, English `descriptions`, `weaknesses`, `references`, and each present `metrics.cvssMetricV40` / `cvssMetricV31` / `cvssMetricV30`. Preserve each score's vector and source/type; do not assume the first metric is authoritative for the user's deployment. `configurations` and CPE ranges describe applicability and need a local version/configuration check. If present, `cisaExploitAdd` reflects inclusion in CISA KEV, not proof this installation is exploitable.

Report the CVE ID and direct NVD record URL (`https://nvd.nist.gov/vuln/detail/CVE-...`) with the retrieval date when presenting live intelligence. Rejected, disputed, or not-yet-analyzed records need explicit qualification.
