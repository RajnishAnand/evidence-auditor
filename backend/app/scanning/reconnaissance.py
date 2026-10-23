import asyncio
import hashlib
from contextlib import asynccontextmanager
from time import monotonic
from urllib.parse import urljoin, urlsplit, urlunsplit
from collections.abc import Callable

import httpx
from bs4 import BeautifulSoup

from backend.app.config import Settings
from backend.app.scanning.authorization import TargetValidationError, resolve_and_validate
from backend.app.scanning.fingerprinting import detect_technologies
from backend.app.scanning.schemas import Evidence, ScanResult, ScanStatus, TechnologyObservation


BROWSER_DOCUMENT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Cache-Control": "no-cache",
}
BROWSER_ASSET_HEADERS = {
    "User-Agent": BROWSER_DOCUMENT_HEADERS["User-Agent"],
    "Accept": "*/*",
    "Accept-Language": BROWSER_DOCUMENT_HEADERS["Accept-Language"],
    "Accept-Encoding": BROWSER_DOCUMENT_HEADERS["Accept-Encoding"],
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


class Reconnaissance:
    def __init__(self, config: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client

    @asynccontextmanager
    async def _http_client(self):
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(follow_redirects=False, verify=True, headers=BROWSER_DOCUMENT_HEADERS) as client:
            yield client

    async def scan(
        self,
        target: str,
        authorization_confirmed: bool,
        follow_redirects: bool | None = True,
        redirect_decider: Callable[[str, str], bool] | None = None,
        progress: Callable[[str], None] | None = None,
        deep_scan: bool = False,
    ) -> ScanResult:
        if not authorization_confirmed:
            return ScanResult(target=target, status=ScanStatus.blocked, errors=["explicit authorization confirmation is required"])
        try:
            if progress:
                progress("Validating target and resolving DNS")
            current, _ = resolve_and_validate(target)
        except TargetValidationError as exc:
            return ScanResult(target=target, status=ScanStatus.blocked, errors=[str(exc)])

        deadline = monotonic() + self.config.scan_deadline_seconds
        redirects: list[str] = []
        resolved_addresses: list[str] = []
        async with self._http_client() as client:
            for _ in range(self.config.max_redirects + 1):
                if monotonic() >= deadline:
                    return ScanResult(target=target, status=ScanStatus.failed, redirects=redirects, errors=["scan deadline exceeded"])
                try:
                    if progress:
                        progress(f"Requesting {current}")
                    current, resolved_addresses = resolve_and_validate(current)
                    remaining = max(0.1, deadline - monotonic())
                    request_timeout = httpx.Timeout(min(self.config.request_timeout_seconds, remaining))
                    async with client.stream("GET", current, headers=BROWSER_DOCUMENT_HEADERS, timeout=request_timeout) as response:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                return ScanResult(target=target, final_url=current, status=ScanStatus.failed, errors=["redirect response had no Location header"])
                            next_url = urljoin(current, location)
                            try:
                                next_url, _ = resolve_and_validate(next_url)
                            except TargetValidationError as exc:
                                return ScanResult(target=target, final_url=current, status=ScanStatus.blocked, redirects=redirects, errors=[f"redirect blocked: {exc}"])
                            should_follow = follow_redirects
                            if follow_redirects is None:
                                should_follow = bool(redirect_decider and redirect_decider(current, next_url))
                            if not should_follow:
                                return ScanResult(
                                    target=target,
                                    final_url=current,
                                    status=ScanStatus.blocked,
                                    http_status=response.status_code,
                                    headers={key.lower(): value for key, value in response.headers.items()},
                                    errors=[f"redirect not followed by user choice; destination was validated as {next_url}"],
                                )
                            redirects.append(next_url)
                            current = next_url
                            continue
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > self.config.max_response_bytes:
                                return ScanResult(target=target, final_url=current, status=ScanStatus.failed, redirects=redirects, errors=["response exceeds configured size limit"])
                        result = self._result(target, current, response, bytes(body), redirects, resolved_addresses)
                        if deep_scan and result.status == ScanStatus.completed:
                            await self._deep_scan_assets(client, result, deadline, progress)
                        return result
                except (TargetValidationError, httpx.HTTPError) as exc:
                    return ScanResult(target=target, final_url=current, status=ScanStatus.failed, redirects=redirects, errors=[str(exc)])
        return ScanResult(target=target, final_url=current, status=ScanStatus.failed, redirects=redirects, errors=["redirect limit exceeded"])

    def _result(self, target: str, current: str, response: httpx.Response, body: bytes, redirects: list[str], resolved_addresses: list[str]) -> ScanResult:
        content_length = response.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.config.max_response_bytes:
            return ScanResult(target=target, final_url=current, status=ScanStatus.failed, redirects=redirects, errors=["response exceeds configured size limit"])
        headers = {key.lower(): value for key, value in response.headers.items()}
        metadata: dict[str, list[str]] = {}
        assets: list[str] = []
        content_type = headers.get("content-type", "")
        if "html" in content_type or not content_type:
            soup = BeautifulSoup(body, "html.parser")
            for tag in soup.find_all("meta"):
                name = tag.get("name") or tag.get("property")
                value = tag.get("content")
                if name and value:
                    metadata.setdefault(name.lower(), []).append(value[:500])
            for tag in soup.find_all(["script", "link"], src=True):
                candidate = tag.get("src") or tag.get("href")
                if candidate:
                    assets.append(urljoin(current, candidate))
            assets = assets[:50]
        cookies = []
        raw_cookies = response.headers.get_list("set-cookie")
        for raw in raw_cookies:
            parts = [part.strip() for part in raw.split(";")]
            cookie = {"name": parts[0].split("=", 1)[0], "attributes": [part.lower() for part in parts[1:]]}
            cookies.append(cookie)
        evidence = [Evidence(source=f"http.header.{key}", value=value) for key, value in headers.items()]
        evidence.extend(Evidence(source="dns.address", value=address) for address in resolved_addresses)
        evidence.extend(self._tls_evidence(response))
        html = body.decode("utf-8", errors="replace") if "html" in content_type or not content_type else ""
        technologies = detect_technologies(headers, metadata, assets, cookies, html=html)
        return ScanResult(target=target, final_url=current, status=ScanStatus.completed, http_status=response.status_code, headers=headers, cookies=cookies, metadata=metadata, referenced_assets=assets, technologies=technologies, evidence=evidence, redirects=redirects)

    async def _deep_scan_assets(self, client: httpx.AsyncClient, result: ScanResult, deadline: float, progress: Callable[[str], None] | None) -> None:
        """Fetch a small same-origin asset set for public version banners."""
        if not result.final_url:
            return
        origin = urlsplit(result.final_url).hostname
        contents: dict[str, str] = {}
        for asset in result.referenced_assets[: self.config.deep_scan_max_assets]:
            if monotonic() >= deadline:
                result.errors.append("deep asset scan deadline exceeded")
                break
            parsed = urlsplit(asset)
            if parsed.hostname != origin or parsed.scheme not in {"http", "https"}:
                result.errors.append(f"deep asset scan skipped external origin: {asset}")
                continue
            try:
                # Target validation rejects query strings by design. For a
                # same-origin asset, validate the origin/path while retaining
                # the query on the actual request (versioned assets commonly
                # use ?ver=...).
                validation_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                resolve_and_validate(validation_url)
                validated = asset
                if progress:
                    progress(f"Inspecting public asset {asset}")
                remaining = max(0.1, deadline - monotonic())
                async with client.stream("GET", validated, headers=BROWSER_ASSET_HEADERS, timeout=httpx.Timeout(min(self.config.request_timeout_seconds, remaining))) as response:
                    content_type = response.headers.get("content-type", "")
                    if content_type and not any(kind in content_type.lower() for kind in ("javascript", "css", "text/")):
                        continue
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.config.deep_scan_max_asset_bytes:
                            result.errors.append(f"deep asset scan skipped oversized asset: {asset}")
                            break
                    else:
                        contents[asset] = bytes(body).decode("utf-8", errors="replace")
                        result.evidence.append(Evidence(source="asset.content", value=asset, limitation="Bounded same-origin asset inspection; content was used for version signatures only."))
            except (TargetValidationError, httpx.HTTPError) as exc:
                result.errors.append(f"deep asset scan failed for {asset}: {exc}")
        discovered = detect_technologies(result.headers, result.metadata, result.referenced_assets, result.cookies, contents)
        combined = result.technologies + discovered
        unique: dict[tuple[str, str | None, str], TechnologyObservation] = {}
        for observation in combined:
            unique[(observation.product, observation.version, observation.rule_id)] = observation
        result.technologies = list(unique.values())

    @staticmethod
    def _tls_evidence(response: httpx.Response) -> list[Evidence]:
        """Extract safe TLS metadata without retaining certificate material."""
        if response.url.scheme.lower() != "https":
            return []
        stream = response.extensions.get("network_stream")
        if stream is None or not hasattr(stream, "get_extra_info"):
            return []
        ssl_object = stream.get_extra_info("ssl_object")
        if ssl_object is None:
            return []
        evidence: list[Evidence] = []
        version = ssl_object.version()
        cipher = ssl_object.cipher()
        certificate = ssl_object.getpeercert(binary_form=True)
        if version:
            evidence.append(Evidence(source="tls.version", value=str(version), limitation="Negotiated connection property observed by the HTTP client."))
        if cipher:
            evidence.append(Evidence(source="tls.cipher", value=str(cipher[0]), limitation="Negotiated connection property observed by the HTTP client."))
        if certificate:
            evidence.append(Evidence(source="tls.certificate.sha256", value=hashlib.sha256(certificate).hexdigest(), limitation="Certificate fingerprint only; certificate validity, hostname coverage, and trust require separate verification."))
        return evidence
