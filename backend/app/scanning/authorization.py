from ipaddress import ip_address
import socket
from urllib.parse import SplitResult, urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """The target is not safe or supported for reconnaissance."""


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise TargetValidationError("target is required")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError("target is not a valid URL") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("only HTTP and HTTPS targets are supported")
    if parsed.username or parsed.password:
        raise TargetValidationError("credentials in target URLs are not allowed")
    if parsed.query or parsed.fragment:
        raise TargetValidationError("query strings and fragments are not allowed")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("target has an invalid port") from exc
    if not hostname:
        raise TargetValidationError("target hostname is required")
    try:
        ascii_host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise TargetValidationError("target hostname is invalid") from exc
    if port is not None and port not in {80, 443}:
        raise TargetValidationError("only ports 80 and 443 are allowed")
    if "/" in ascii_host or "@" in ascii_host:
        raise TargetValidationError("target hostname is invalid")
    return urlunsplit((parsed.scheme.lower(), ascii_host + (f":{port}" if port else ""), parsed.path or "/", "", ""))


def _is_forbidden_address(address: str) -> bool:
    ip = ip_address(address)
    return any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified))


def resolve_and_validate(url: str) -> tuple[str, list[str]]:
    """Resolve a URL's host and reject destinations that are not public.

    This is performed before every request and redirect. Network policy outside
    the process/container is still recommended; DNS validation cannot eliminate
    every race without a resolver and connection-pinning layer.
    """
    normalized = normalize_target(url)
    parsed: SplitResult = urlsplit(normalized)
    host = parsed.hostname
    assert host is not None
    try:
        literal = ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetValidationError(f"DNS resolution failed for {host}") from exc
        addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise TargetValidationError(f"no addresses found for {host}")
    forbidden = [address for address in addresses if _is_forbidden_address(address)]
    if forbidden:
        raise TargetValidationError("target resolves to a private, local, reserved, or metadata-like address")
    return normalized, addresses
