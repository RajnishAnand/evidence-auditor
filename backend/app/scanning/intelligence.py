"""Small NVD client for clearly labelled vulnerability candidates."""

import asyncio
import re
from datetime import datetime
from typing import Any

import httpx

from backend.app.scanning.schemas import TechnologyObservation, VulnerabilityCandidate

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_PACKAGES = {"Express": ("npm", "express"), "Next.js": ("npm", "next"), "Nuxt": ("npm", "nuxt")}


class IntelligenceError(RuntimeError):
    pass


class NvdClient:
    def __init__(self, client: httpx.AsyncClient | None = None, max_results: int = 5, max_retries: int = 2) -> None:
        self.client = client
        self.max_results = max_results
        self.max_retries = max(0, max_retries)

    async def search(self, technology: TechnologyObservation) -> list[VulnerabilityCandidate]:
        params = {"keywordSearch": technology.product, "resultsPerPage": str(self.max_results)}
        if technology.version:
            params["keywordSearch"] = f"{technology.product} {technology.version}"
        owned_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=httpx.Timeout(10), headers={"User-Agent": "evidence-auditor/0.1"})
        try:
            for attempt in range(self.max_retries + 1):
                response = await client.get(NVD_ENDPOINT, params=params)
                if response.status_code not in {429, 500, 502, 503, 504} or attempt == self.max_retries:
                    break
                retry_after = response.headers.get("retry-after", "")
                try:
                    delay = min(2.0, max(0.0, float(retry_after)))
                except ValueError:
                    delay = 0.1 * (attempt + 1)
                await asyncio.sleep(delay)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IntelligenceError(f"NVD lookup failed for {technology.product}: {exc}") from exc
        finally:
            if owned_client:
                await client.aclose()
        candidates: list[VulnerabilityCandidate] = []
        for item in payload.get("vulnerabilities", []):
            candidate = self._candidate(item, technology)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    def _candidate(self, item: dict[str, Any], technology: TechnologyObservation) -> VulnerabilityCandidate | None:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            return None
        descriptions = cve.get("descriptions") or []
        summary = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "No English description provided.")
        metrics = cve.get("metrics") or {}
        metric = next((metrics.get(name, [{}])[0] for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if metrics.get(name)), {})
        cvss = metric.get("cvssData") or {}
        published = self._date(cve.get("published"))
        modified = self._date(cve.get("lastModified"))
        confidence, limitation = self._applicability(cve, technology.version)
        return VulnerabilityCandidate(
            cve_id=cve_id,
            product=technology.product,
            summary=summary,
            advisory_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            severity=metric.get("baseSeverity") or cvss.get("baseSeverity"),
            cvss_score=cvss.get("baseScore"),
            published=published,
            modified=modified,
            matched_version=technology.version,
            applicability_confidence=confidence,
            limitation=limitation,
        )

    @classmethod
    def _applicability(cls, cve: dict[str, Any], version: str | None) -> tuple[float, str]:
        base = "Candidate from an NVD keyword search. Product-name matching does not establish affected-version applicability; verify version ranges, patches, configuration, and prerequisites."
        if not version:
            return 0.2, base
        observed = cls._version_key(version)
        if observed is None:
            return 0.2, base + " The observed version format could not be compared safely."
        ranges: list[dict[str, str]] = []
        for value in cls._walk(cve.get("configurations", {}), "cpeMatch"):
            if any(key in value for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")):
                ranges.append(value)
        if not ranges:
            return 0.35, base
        for item in ranges:
            if cls._in_range(observed, item):
                return 0.65, base + " The observed version falls within an explicit NVD CPE range; verify the product identity and prerequisites."
        return 0.1, base + " The observed version falls outside the explicit NVD CPE ranges returned for this candidate; this is not proof of safety because CPE coverage may be incomplete."

    @staticmethod
    def _walk(value: Any, key: str) -> list[dict[str, str]]:
        found: list[dict[str, str]] = []
        if isinstance(value, dict):
            if key in value and isinstance(value[key], list):
                found.extend(item for item in value[key] if isinstance(item, dict))
            for child in value.values():
                found.extend(NvdClient._walk(child, key))
        elif isinstance(value, list):
            for child in value:
                found.extend(NvdClient._walk(child, key))
        return found

    @staticmethod
    def _version_key(value: str) -> tuple[int, ...] | None:
        match = re.match(r"^\s*(\d+(?:\.\d+)*)", value)
        return tuple(int(part) for part in match.group(1).split(".")) if match else None

    @classmethod
    def _in_range(cls, observed: tuple[int, ...], item: dict[str, str]) -> bool:
        def compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
            size = max(len(left), len(right))
            a, b = left + (0,) * (size - len(left)), right + (0,) * (size - len(right))
            return (a > b) - (a < b)

        for key, inclusive, direction in (
            ("versionStartIncluding", True, 1), ("versionStartExcluding", False, 1),
            ("versionEndIncluding", True, -1), ("versionEndExcluding", False, -1),
        ):
            bound = cls._version_key(item.get(key, ""))
            if bound is None:
                continue
            result = compare(observed, bound)
            if direction == 1 and (result < 0 or (result == 0 and not inclusive)):
                return False
            if direction == -1 and (result > 0 or (result == 0 and not inclusive)):
                return False
        return True

    @staticmethod
    def _date(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


class OsvClient:
    """Query OSV only when a detected product maps to a package identity."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.client = client

    async def search(self, technology: TechnologyObservation) -> list[VulnerabilityCandidate]:
        package = OSV_PACKAGES.get(technology.product)
        if package is None or not technology.version:
            return []
        owned_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=httpx.Timeout(10), headers={"User-Agent": "evidence-auditor/0.1"})
        try:
            response = await client.post(OSV_ENDPOINT, json={"package": {"ecosystem": package[0], "name": package[1]}, "version": technology.version})
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IntelligenceError(f"OSV lookup failed for {technology.product}: {exc}") from exc
        finally:
            if owned_client:
                await client.aclose()
        candidates: list[VulnerabilityCandidate] = []
        for item in payload.get("vulns", []):
            candidate = self._candidate(item, technology)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    @staticmethod
    def _candidate(item: dict[str, Any], technology: TechnologyObservation) -> VulnerabilityCandidate | None:
        identifier = next(iter(item.get("aliases") or []), item.get("id"))
        if not identifier:
            return None
        return VulnerabilityCandidate(
            cve_id=identifier,
            product=technology.product,
            summary=item.get("summary") or "No summary provided by OSV.",
            source="OSV",
            advisory_url=f"https://osv.dev/vulnerability/{item.get('id', identifier)}",
            matched_version=technology.version,
            applicability_confidence=0.55,
            limitation="OSV matched a package and reported version, but applicability still requires verifying deployment, configuration, and vendor backports.",
        )
async def find_candidates(technologies: list[TechnologyObservation], client: httpx.AsyncClient | None = None) -> tuple[list[VulnerabilityCandidate], list[str]]:
    """Search each distinct product and retain source-linked candidates."""
    nvd = NvdClient(client=client)
    osv = OsvClient(client=client)
    results: list[VulnerabilityCandidate] = []
    errors: list[str] = []
    seen_products: set[str] = set()
    for technology in technologies:
        if technology.product in seen_products:
            continue
        seen_products.add(technology.product)
        try:
            product_results = await nvd.search(technology)
            results.extend(product_results)
            if not product_results:
                errors.append(
                    f"NVD returned no candidates for {technology.product}; "
                    "this does not establish that the target is secure."
                )
        except IntelligenceError as exc:
            errors.append(str(exc))
        try:
            results.extend(await osv.search(technology))
        except IntelligenceError as exc:
            errors.append(str(exc))
    unique = {candidate.cve_id: candidate for candidate in results}
    return list(unique.values()), errors
