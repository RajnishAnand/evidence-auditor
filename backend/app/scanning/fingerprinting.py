"""Conservative, evidence-backed technology fingerprint rules."""

import re
from collections.abc import Iterable

from backend.app.scanning.schemas import TechnologyObservation


def _version(value: str, pattern: str) -> str | None:
    match = re.search(pattern, value, re.IGNORECASE)
    return match.group(1) if match else None


def _observation(
    product: str,
    category: str,
    rule_id: str,
    value: str,
    source: str,
    confidence: float,
    version: str | None = None,
) -> TechnologyObservation:
    return TechnologyObservation(
        product=product,
        category=category,
        version=version,
        rule_id=rule_id,
        observed_value=value,
        evidence_source=source,
        confidence=confidence,
        limitation="Externally observed signature; this does not prove the origin server or installed version.",
    )


def detect_technologies(
    headers: dict[str, str], metadata: dict[str, list[str]], assets: Iterable[str], cookies: Iterable[dict[str, object]] | None = None, asset_contents: dict[str, str] | None = None, html: str = ""
) -> list[TechnologyObservation]:
    observations: list[TechnologyObservation] = []

    server = headers.get("server", "")
    server_rules = (
        ("nginx", "web_server", r"nginx(?:/([0-9][^\s]*)?)?", "server-nginx"),
        ("Apache HTTP Server", "web_server", r"Apache(?:/([0-9][^\s]*)?)?", "server-apache"),
        ("Microsoft IIS", "web_server", r"Microsoft-IIS(?:/([0-9][^\s]*)?)?", "server-iis"),
        ("LiteSpeed", "web_server", r"LiteSpeed(?:/([0-9][^\s]*)?)?", "server-litespeed"),
        ("OpenResty", "web_server", r"openresty(?:/([0-9][^\s]*)?)?", "server-openresty"),
        ("Caddy", "web_server", r"Caddy(?:/([0-9][^\s]*)?)?", "server-caddy"),
        ("Gunicorn", "application_server", r"gunicorn(?:/([0-9][^\s]*)?)?", "server-gunicorn"),
        ("Uvicorn", "application_server", r"uvicorn(?:/([0-9][^\s]*)?)?", "server-uvicorn"),
        ("Apache Tomcat", "application_server", r"Apache-Coyote|Tomcat(?:/([0-9][^\s]*)?)?", "server-tomcat"),
        ("Jetty", "application_server", r"Jetty(?:/([0-9][^\s]*)?)?", "server-jetty"),
        ("Kestrel", "application_server", r"Kestrel(?:/([0-9][^\s]*)?)?", "server-kestrel"),
    )
    for product, category, pattern, rule_id in server_rules:
        if re.search(pattern, server, re.IGNORECASE):
            observations.append(_observation(product, category, rule_id, server, "http.header.server", 0.95, _version(server, pattern)))

    powered_by = headers.get("x-powered-by", "")
    powered_rules = (
        ("Express", "framework", r"Express(?:\s*[/ ]\s*([0-9][^\s]*))?", "powered-by-express"),
        ("PHP", "runtime", r"PHP(?:/|\s+)?([0-9][^\s]*)?", "powered-by-php"),
        ("ASP.NET", "framework", r"ASP\.NET(?:\s+([0-9][^\s]*))?", "powered-by-aspnet"),
        ("Phusion Passenger", "application_server", r"Phusion Passenger(?:/|\s+)?([0-9][^\s]*)?", "powered-by-passenger"),
    )
    for product, category, pattern, rule_id in powered_rules:
        if re.search(pattern, powered_by, re.IGNORECASE):
            observations.append(_observation(product, category, rule_id, powered_by, "http.header.x-powered-by", 0.9, _version(powered_by, pattern)))

    version_header_rules = (
        ("ASP.NET", "framework", "x-aspnet-version", r"([0-9]+(?:\.[0-9]+)+)", "header-aspnet-version"),
        ("ASP.NET", "framework", "x-aspnetmvc-version", r"([0-9]+(?:\.[0-9]+)+)", "header-aspnetmvc-version"),
    )
    for product, category, header, pattern, rule_id in version_header_rules:
        value = headers.get(header, "")
        if value:
            observations.append(_observation(product, category, rule_id, value, f"http.header.{header}", 0.9, _version(value, pattern)))

    edge_signatures = (
        ("Cloudflare", "cdn", "cf-ray", "header-cdn-cloudflare"),
        ("Amazon CloudFront", "cdn", "x-amz-cf-id", "header-cdn-cloudfront"),
        ("Fastly", "cdn", "x-served-by", "header-cdn-fastly"),
    )
    for product, category, header, rule_id in edge_signatures:
        value = headers.get(header, "")
        if value:
            observations.append(_observation(product, category, rule_id, value, f"http.header.{header}", 0.85))

    generators = metadata.get("generator", [])
    generator_rules = (
        ("WordPress", "cms", r"WordPress\s*([0-9][^\s]*)?", "meta-generator-wordpress"),
        ("Drupal", "cms", r"Drupal\s*([0-9][^\s]*)?", "meta-generator-drupal"),
        ("Joomla", "cms", r"Joomla!?\s*([0-9][^\s]*)?", "meta-generator-joomla"),
        ("Ghost", "cms", r"Ghost\s*([0-9][^\s]*)?", "meta-generator-ghost"),
        ("Shopify", "commerce", r"Shopify\s*([0-9][^\s]*)?", "meta-generator-shopify"),
    )
    for value in generators:
        for product, category, pattern, rule_id in generator_rules:
            if re.search(pattern, value, re.IGNORECASE):
                observations.append(_observation(product, category, rule_id, value, "html.meta.generator", 0.95, _version(value, pattern)))

    asset_values = list(assets)
    asset_rules = (
        ("WordPress", "cms", r"/(?:wp-content|wp-includes)(?:/|$)", "asset-path-wordpress"),
        ("Next.js", "framework", r"/_next/(?:static|image)(?:/|$)", "asset-path-nextjs"),
        ("Drupal", "cms", r"/sites/default/files/", "asset-path-drupal"),
        ("Nuxt", "framework", r"/_nuxt/(?:[^/]+/)?", "asset-path-nuxt"),
        ("Shopify", "commerce", r"(?:^|/)cdn\.shopify\.com/", "asset-path-shopify"),
        ("PHP", "runtime", r"\.php(?:[?#]|$)", "asset-path-php"),
    )
    for asset in asset_values:
        for product, category, pattern, rule_id in asset_rules:
            if re.search(pattern, asset, re.IGNORECASE):
                observations.append(_observation(product, category, rule_id, asset, "html.asset.reference", 0.8, None))
    asset_version_rules = (
        ("jQuery", "javascript_library", r"(?:^|/)jquery(?:[-.]|\.min\.)([0-9]+(?:\.[0-9]+)+)", "asset-version-jquery"),
        ("Bootstrap", "javascript_library", r"(?:^|/)bootstrap(?:[-.]|\.min\.)([0-9]+(?:\.[0-9]+)+)", "asset-version-bootstrap"),
        ("Vue.js", "javascript_library", r"(?:^|/)vue(?:[-.]|\.min\.)([0-9]+(?:\.[0-9]+)+)", "asset-version-vue"),
    )
    for asset in asset_values:
        for product, category, pattern, rule_id in asset_version_rules:
            version = _version(asset, pattern)
            if version:
                observations.append(_observation(product, category, rule_id, asset, "html.asset.reference", 0.7, version))

    cookie_names = {str(cookie.get("name", "")).lower() for cookie in (cookies or [])}
    cookie_rules = (
        ("PHP", "runtime", "phpsessid", "cookie-phpsessid", 0.9),
        ("ASP.NET", "framework", "asp.net_sessionid", "cookie-aspnet-session", 0.9),
        ("Java Servlet", "runtime", "jsessionid", "cookie-jsessionid", 0.85),
        ("Ruby on Rails", "framework", "_session_id", "cookie-rails-session", 0.8),
        ("Django", "framework", "csrftoken", "cookie-django-csrf", 0.65),
        ("Django", "framework", "django_session", "cookie-django-session", 0.8),
        ("Express", "framework", "connect.sid", "cookie-connect-sid", 0.75),
        ("Laravel", "framework", "laravel_session", "cookie-laravel-session", 0.9),
        ("Ruby on Rails", "framework", "_rails_session", "cookie-rails-session", 0.8),
        ("Ruby Rack", "framework", "rack.session", "cookie-rack-session", 0.65),
    )
    for product, category, cookie_name, rule_id, confidence in cookie_rules:
        if cookie_name in cookie_names:
            observations.append(_observation(product, category, rule_id, cookie_name, "http.cookie.name", confidence))

    html_rules = (
        ("Ruby on Rails", "framework", r"(?:name|content)=['\"]authenticity_token['\"]", "html-rails-authenticity-token", 0.8),
        ("Angular", "framework", r"\bng-version=['\"]([0-9]+(?:\.[0-9]+)+)['\"]", "html-angular-version", 0.9),
        ("ASP.NET", "framework", r"__VIEWSTATE", "html-aspnet-viewstate", 0.8),
        ("Java Server Pages", "runtime", r"\.jsp(?:[?#\"']|$)", "html-jsp-reference", 0.65),
        ("ASP.NET", "framework", r"\.aspx(?:[?#\"']|$)", "html-aspx-reference", 0.65),
    )
    for product, category, pattern, rule_id, confidence in html_rules:
        match = re.search(pattern, html[:1_000_000], re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else None
            observations.append(_observation(product, category, rule_id, match.group(0)[:200], "html.body", confidence, version))

    content_rules = (
        ("jQuery", "javascript_library", r"jQuery\s+v([0-9]+(?:\.[0-9]+)+)", "asset-content-jquery"),
        ("React", "javascript_library", r"(?:React|react)[^\n]{0,30}?[v@]([0-9]+(?:\.[0-9]+)+)", "asset-content-react"),
        ("Vue.js", "javascript_library", r"Vue(?:\.js)?\s+v([0-9]+(?:\.[0-9]+)+)", "asset-content-vue"),
        ("Bootstrap", "javascript_library", r"Bootstrap\s+v([0-9]+(?:\.[0-9]+)+)", "asset-content-bootstrap"),
        ("Angular", "framework", r"(?:@angular/core|ng-version)[^0-9]{0,10}([0-9]+(?:\.[0-9]+)+)", "asset-content-angular"),
    )
    for asset_url, content in (asset_contents or {}).items():
        for product, category, pattern, rule_id in content_rules:
            match = re.search(pattern, content[:500_000], re.IGNORECASE)
            if match:
                observations.append(_observation(product, category, rule_id, match.group(0)[:200], "asset.content", 0.75, match.group(1)))

    unique: dict[tuple[str, str | None, str], TechnologyObservation] = {}
    for observation in observations:
        unique[(observation.product, observation.version, observation.rule_id)] = observation
    return list(unique.values())
