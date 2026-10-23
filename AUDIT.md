# Change Audit

**Audit author:** Aegis (OpenCode coding agent)  
**Audit date:** 2026-10-24  
**Repository:** `RajnishAnand/evidence-auditor`

## Reviewed scope

- Authorization-gated, bounded HTTP/HTTPS reconnaissance.
- Redirect validation and just-in-time user confirmation.
- Browser-compatible request headers without claiming stealth or evasion.
- Header, cookie, HTML, asset-path, TLS, and bounded asset-content detection.
- NVD and OSV candidate correlation with explicit uncertainty.
- SQLite scan preservation and local working progress tracking.
- TUI flow, scan-summary page, progress spinner, result table, and confidence labels.

## Validation

```text
32 tests passed
```

## Audit conclusions

- Findings remain evidence-based observations or vulnerability candidates; they
  are not proof of origin infrastructure, exploitability, or security.
- Exact backend versions are only reported when a public signal establishes the
  version. Proxy-hidden Rails, Node.js, PHP, and other origins may remain
  undetected.
- Deep scanning is opt-in, same-origin, bounded by count/size/time, and limited
  to public assets.
- `PROGRESS.md`, local databases, logs, environments, and caches are excluded
  from Git publication.

## Open risks

DNS-to-connection pinning, isolated egress policy, vendor advisory correlation,
vulnerability caching, independently versioned fingerprint rules, and broader
precision testing remain future work.
