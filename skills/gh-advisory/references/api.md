# GitHub global advisory REST API

Official documentation: <https://docs.github.com/en/rest/security-advisories/global-advisories>. Public global advisories can be read without authentication; `gh api` requires a configured GitHub CLI session. Repository-specific advisories are a different API and may require permissions.

Compatibility checked on 2026-10-13: public REST and `gh api` single-advisory requests returned `GHSA-c2m8-4gcg-v22g`. List filters below follow GitHub's documentation but were not live-tested here.

## Bounded queries

```bash
gh api /advisories/GHSA-c2m8-4gcg-v22g
gh api '/advisories?cve_id=CVE-2024-3094&per_page=10'
gh api '/advisories?ecosystem=rust&affects=example-crate%401.2.3&per_page=10'
```

For public records without `gh`, GET `https://api.github.com/advisories/GHSA-ID` or `https://api.github.com/advisories?cve_id=CVE-ID&per_page=10` with `Accept: application/vnd.github+json`. Encode package names and versions in `affects`. The list API supports `ghsa_id`, `cve_id`, `ecosystem`, `severity`, `type`, `cwes`, `affects`, `published`, `updated`, and pagination. Use the documented parameter names; `cwes` and `is_withdrawn` are current names, not `cwe_ids` or `state`.

## Interpret the response

Check `ghsa_id`, `cve_id`, `type`, `withdrawn_at`, `published_at`, `updated_at`, `vulnerabilities[].package.{ecosystem,name}`, `vulnerable_version_range`, and `first_patched_version`. Compare the exact installed version and any affected function or configuration with local evidence. `cvss_severities.cvss_v3` and `cvss_severities.cvss_v4` may coexist; retain version and vector with each score. The older `cvss` field may describe a different version. Check `cwes` and `references` without treating either as proof.

Follow pagination only as needed. Record the advisory URL and retrieval date when presenting live results. A missing advisory or a withdrawn/unreviewed one needs qualification; it does not establish that local code is safe or vulnerable.
