import socket

import pytest

from backend.app.scanning.authorization import TargetValidationError, normalize_target, resolve_and_validate


def test_normalizes_hostname_and_path():
    assert normalize_target("EXAMPLE.com") == "https://example.com/"


@pytest.mark.parametrize("target", ["ftp://example.com", "http://user:pass@example.com", "http://example.com:8080", "http://example.com?a=1"])
def test_rejects_unsafe_url_shapes(target: str):
    with pytest.raises(TargetValidationError):
        normalize_target(target)


def test_rejects_private_literal():
    with pytest.raises(TargetValidationError):
        resolve_and_validate("http://127.0.0.1")


def test_rejects_private_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(TargetValidationError):
        resolve_and_validate("https://internal.example")


def test_reports_dns_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(TargetValidationError, match="DNS resolution failed"):
        resolve_and_validate("https://missing.example")
