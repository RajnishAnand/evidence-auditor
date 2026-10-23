import json

import httpx
import pytest
import respx

from backend.app.scanning.intelligence import NVD_ENDPOINT, OSV_ENDPOINT, NvdClient, OsvClient, find_candidates
from backend.app.scanning.schemas import TechnologyObservation


@pytest.mark.asyncio
@respx.mock
async def test_nvd_candidate_preserves_source_and_uncertainty():
    route = respx.get(NVD_ENDPOINT).mock(return_value=httpx.Response(200, json={"vulnerabilities": [{"cve": {
        "id": "CVE-2024-0001",
        "published": "2024-01-01T00:00:00.000Z",
        "lastModified": "2024-01-02T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "Example issue."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
    }}]}))
    technology = TechnologyObservation(product="nginx", category="web_server", rule_id="test", observed_value="nginx/1.2", evidence_source="test", confidence=0.9, limitation="test", version="1.2")
    results = await NvdClient().search(technology)
    assert route.called
    assert results[0].cve_id == "CVE-2024-0001"
    assert results[0].status == "candidate"
    assert results[0].applicability_confidence == 0.35
    assert "does not establish" in results[0].limitation


@pytest.mark.asyncio
@respx.mock
async def test_no_nvd_match_is_reported_as_a_limitation():
    respx.get(NVD_ENDPOINT).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    technology = TechnologyObservation(
        product="custom-runtime",
        category="runtime",
        rule_id="test",
        observed_value="custom-runtime",
        evidence_source="test",
        confidence=0.8,
        limitation="test",
    )

    candidates, errors = await find_candidates([technology])

    assert candidates == []
    assert errors == [
        "NVD returned no candidates for custom-runtime; this does not establish that the target is secure."
    ]


@pytest.mark.asyncio
@respx.mock
async def test_nvd_retries_transient_rate_limit():
    route = respx.get(NVD_ENDPOINT).mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "0"}),
            httpx.Response(200, json={"vulnerabilities": []}),
        ]
    )
    technology = TechnologyObservation(
        product="nginx", category="web_server", rule_id="test",
        observed_value="nginx", evidence_source="test", confidence=0.9, limitation="test",
    )

    results = await NvdClient(max_retries=1).search(technology)

    assert results == []
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_osv_matches_known_package_identity_and_version():
    route = respx.post(OSV_ENDPOINT).mock(return_value=httpx.Response(200, json={"vulns": [{
        "id": "GHSA-example",
        "aliases": ["CVE-2024-0002"],
        "summary": "Example package issue",
    }]}))
    technology = TechnologyObservation(
        product="Express", category="framework", version="4.18.2", rule_id="test",
        observed_value="Express 4.18.2", evidence_source="test", confidence=0.9, limitation="test",
    )

    results = await OsvClient().search(technology)

    assert route.called
    request = json.loads(route.calls[0].request.content)
    assert request == {"package": {"ecosystem": "npm", "name": "express"}, "version": "4.18.2"}
    assert results[0].cve_id == "CVE-2024-0002"
    assert results[0].source == "OSV"


def test_nvd_version_range_changes_confidence_conservatively():
    technology = TechnologyObservation(
        product="nginx", category="web_server", version="1.2.3", rule_id="test",
        observed_value="nginx/1.2.3", evidence_source="test", confidence=0.9, limitation="test",
    )
    item = {"cve": {"id": "CVE-2024-0003", "configurations": [{"nodes": [{"cpeMatch": [{
        "versionStartIncluding": "1.0", "versionEndExcluding": "1.3"
    }]}]}]}}

    candidate = NvdClient()._candidate(item, technology)

    assert candidate is not None
    assert candidate.applicability_confidence == 0.65
    assert "falls within" in candidate.limitation
