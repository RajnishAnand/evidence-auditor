# Evidence Auditor

Evidence Auditor is a conservative, terminal-first website reconnaissance tool
for targets you own or are explicitly authorized to assess. It collects public
HTTP/DNS/TLS observations, identifies technologies when evidence supports the
claim, and labels public vulnerability results as candidates rather than proof
of exploitability.

## Safety model

- Requires an explicit authorization confirmation before scanning.
- Supports HTTP and HTTPS only; rejects credentials, query targets, unusual
  ports, and private/reserved/link-local destinations.
- Resolves and validates every request and redirect destination.
- Uses bounded timeouts, redirect counts, response sizes, and asset downloads.
- Redirects prompt at the moment they are encountered.
- Deep scanning is opt-in and limited to same-origin public assets.
- No brute force, authentication bypass, exploitation, or destructive actions.

Browser-compatible request headers are used for normal compatibility. They are
not a stealth guarantee: TLS characteristics, timing, request patterns, and
the absence of browser execution may still identify automation.

## Quick start

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
./run.sh
```

The TUI first asks for a URL, then shows a scan summary where authorization and
the optional bounded deep scan can be selected. Press `q` to quit. Results can
be scrolled with arrows, PgUp/PgDn, Home, and End. Press `v` after a scan to
query NVD and OSV candidates for detected package technologies.

Run tests with:

```bash
./.venv/bin/python -m pytest -q
```

## Configuration

Copy `.env.example` to `.env` and adjust only within a controlled environment:

```dotenv
AUDITOR_MAX_RESPONSE_BYTES=1048576
AUDITOR_REQUEST_TIMEOUT_SECONDS=10
AUDITOR_SCAN_DEADLINE_SECONDS=30
AUDITOR_MAX_REDIRECTS=5
AUDITOR_DEEP_SCAN_MAX_ASSETS=10
AUDITOR_DEEP_SCAN_MAX_ASSET_BYTES=262144
AUDITOR_DATABASE_PATH=evidence_auditor.sqlite3
```

Completed scans are stored locally in SQLite. The database, logs, environment
file, and `PROGRESS.md` are ignored by Git. `PROGRESS.md` is a local working
log and is not part of the published project history.

## Detection and intelligence

Detection uses response headers, cookie names, HTML/meta markers, public asset
paths, TLS metadata, and bounded same-origin asset content. Exact versions are
reported only when an exposed signal establishes one. Reverse proxies and
sanitized headers can hide Rails, Node.js, PHP, or other origin technologies;
absence of a match is not evidence of absence.

See [`POPULAR_BACKENDS.md`](POPULAR_BACKENDS.md) for the detection matrix and
research references. NVD keyword results and OSV package results are clearly
marked as candidates and require version, configuration, patch, and prerequisite
verification.

## Technology certainty

The TUI displays detected technologies in a checkbox-style table. `[x]` means
that at least one public signal matched a rule; it does **not** mean the
technology is proven to be installed at the origin.

| Display | Score | Meaning | Typical evidence |
| --- | ---: | --- | --- |
| `HIGH` | `0.85–1.00` | Strong public signature, still externally observed | Explicit version-bearing `Server`/`X-Powered-By` header, exact framework cookie, exact generator metadata |
| `MED` | `0.60–0.84` | Useful corroborating hint | Stable asset path, framework cookie with alternatives, HTML marker, bounded bundle signature |
| `LOW` | `0.00–0.59` | Weak or ambiguous hint | Generic path, single weak header, indirect platform relationship |

Confidence is rule-defined evidence strength, not statistical probability. A
reverse proxy can hide the origin, cookie names can be changed, and a public
asset can be copied by another application. Unknown versions are intentionally
shown as `unknown`; the auditor does not invent a version from a product name.

Example:

```text
[x] TECHNOLOGY                    CATEGORY             VERSION       CONFIDENCE
[x] nginx                         web_server           1.24.0        HIGH 0.95
    http.header.server: nginx/1.24.0
```

## Project status

The local validation suite currently passes 32 tests. Larger production-grade
items remain, including DNS-to-connection pinning, vendor advisory correlation,
vulnerability caching, independently versioned fingerprint rules, and broader
precision testing.

## License

No license has been selected yet. Treat this repository as all-rights-reserved
until a project license is added.
