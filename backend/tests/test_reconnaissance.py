import httpx
import pytest
import respx

from backend.app.config import Settings
from backend.app.scanning.reconnaissance import Reconnaissance


@pytest.fixture
def config():
    return Settings(scan_deadline_seconds=5, request_timeout_seconds=2, max_response_bytes=10000)


@pytest.mark.asyncio
@respx.mock
async def test_collects_headers_metadata_cookies_and_redirects(config, monkeypatch):
    async def public(*args, **kwargs):
        return ("93.184.216.34",)
    monkeypatch.setattr("backend.app.scanning.authorization.resolve_and_validate", lambda url: (url, ["93.184.216.34"]))
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "https://example.com/home"}))
    respx.get("https://example.com/home").mock(return_value=httpx.Response(200, headers={"content-type": "text/html", "x-powered-by": "Example/1.2", "set-cookie": "sid=x; Secure; HttpOnly"}, text='<meta name="generator" content="Example"><script src="/app.js"></script>'))
    result = await Reconnaissance(config).scan("example.com", True)
    assert result.http_status == 200
    assert result.metadata["generator"] == ["Example"]
    assert result.cookies[0]["name"] == "sid"
    assert result.redirects == ["https://example.com/home"]


@pytest.mark.asyncio
async def test_requires_authorization(config):
    result = await Reconnaissance(config).scan("example.com", False)
    assert result.status == "blocked"


@pytest.mark.asyncio
@respx.mock
async def test_blocks_redirect_to_private_target(config, monkeypatch):
    monkeypatch.setattr("backend.app.scanning.authorization.resolve_and_validate", lambda url: (url, ["93.184.216.34"]) if "example.com" in url else (_ for _ in ()).throw(Exception("private")))
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/"}))
    result = await Reconnaissance(config).scan("example.com", True)
    assert result.status in {"blocked", "failed"}


@pytest.mark.asyncio
@respx.mock
async def test_can_stop_before_following_valid_redirect(config, monkeypatch):
    monkeypatch.setattr("backend.app.scanning.authorization.resolve_and_validate", lambda url: (url, ["93.184.216.34"]))
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "https://example.com/home"}))

    result = await Reconnaissance(config).scan("example.com", True, follow_redirects=False)

    assert result.status == "blocked"
    assert result.http_status == 302
    assert "not followed by user choice" in result.errors[0]


@pytest.mark.asyncio
@respx.mock
async def test_redirect_decider_is_called_only_when_redirect_is_seen(config, monkeypatch):
    monkeypatch.setattr("backend.app.scanning.authorization.resolve_and_validate", lambda url: (url, ["93.184.216.34"]))
    respx.get("https://example.com/").mock(return_value=httpx.Response(302, headers={"location": "https://example.com/home"}))
    respx.get("https://example.com/home").mock(return_value=httpx.Response(200, text="ok"))
    prompts: list[tuple[str, str]] = []
    progress: list[str] = []

    result = await Reconnaissance(config).scan(
        "example.com", True, follow_redirects=None,
        redirect_decider=lambda source, destination: prompts.append((source, destination)) or True,
        progress=progress.append,
    )

    assert result.http_status == 200
    assert prompts == [("https://example.com/", "https://example.com/home")]
    assert any(item.startswith("Requesting") for item in progress)


@pytest.mark.asyncio
@respx.mock
async def test_deep_scan_extracts_version_from_same_origin_asset(config, monkeypatch):
    monkeypatch.setattr("backend.app.scanning.authorization.resolve_and_validate", lambda url: (url, ["93.184.216.34"]))
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200,
        headers={"content-type": "text/html"},
        text='<script src="/assets/vendor.js"></script>',
    ))
    respx.get("https://example.com/assets/vendor.js").mock(return_value=httpx.Response(
        200,
        headers={"content-type": "application/javascript"},
        text="/*! jQuery v3.7.1 | https://jquery.com */",
    ))

    result = await Reconnaissance(config).scan("example.com", True, deep_scan=True)

    assert any(item.product == "jQuery" and item.version == "3.7.1" for item in result.technologies)
    assert respx.calls[0].request.headers["sec-fetch-dest"] == "document"
    assert respx.calls[1].request.headers["sec-fetch-dest"] == "script"


def test_tls_evidence_is_metadata_only():
    class FakeSSL:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, binary_form=False):
            assert binary_form is True
            return b"certificate-bytes"

    class FakeStream:
        def get_extra_info(self, name):
            return FakeSSL() if name == "ssl_object" else None

    response = httpx.Response(200, request=httpx.Request("GET", "https://example.com/"), extensions={"network_stream": FakeStream()})
    evidence = Reconnaissance._tls_evidence(response)

    assert [item.source for item in evidence] == ["tls.version", "tls.cipher", "tls.certificate.sha256"]
    assert all("certificate-bytes" not in item.value for item in evidence)
