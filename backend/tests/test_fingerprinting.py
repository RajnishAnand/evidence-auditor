from backend.app.scanning.fingerprinting import detect_technologies


def test_detects_direct_signatures_and_preserves_unknown_versions():
    observations = detect_technologies(
        {"server": "nginx/1.24.0", "x-powered-by": "Express"},
        {"generator": ["WordPress 6.5.2"]},
        ["https://example.com/wp-content/themes/site/app.js"],
    )
    assert any(item.product == "nginx" and item.version == "1.24.0" for item in observations)
    assert any(item.product == "Express" and item.version is None for item in observations)
    assert any(item.product == "WordPress" and item.version == "6.5.2" for item in observations)
    assert any(item.rule_id == "asset-path-wordpress" for item in observations)


def test_does_not_invent_product_from_unrecognized_values():
    observations = detect_technologies({"server": "custom-edge"}, {"generator": ["custom platform"]}, [])
    assert observations == []


def test_detects_additional_framework_and_platform_signatures():
    observations = detect_technologies(
        {"x-aspnet-version": "4.8", "server": "edge"},
        {"generator": ["Ghost 5.90"]},
        ["https://example.com/_nuxt/app.js", "https://cdn.shopify.com/theme.js"],
    )

    assert any(item.product == "ASP.NET" and item.version == "4.8" for item in observations)
    assert any(item.product == "Ghost" and item.version == "5.90" for item in observations)
    assert any(item.product == "Nuxt" for item in observations)
    assert any(item.product == "Shopify" for item in observations)


def test_detects_explicit_cdn_headers_only():
    observations = detect_technologies({"cf-ray": "abc", "server": "edge"}, {}, [])
    assert [(item.product, item.category) for item in observations] == [("Cloudflare", "cdn")]


def test_detects_php_from_session_cookie_and_php_asset():
    observations = detect_technologies(
        {"server": "Apache"}, {}, ["https://example.com/account.php"],
        [{"name": "PHPSESSID", "attributes": ["httponly"]}],
    )
    php = [item for item in observations if item.product == "PHP"]
    assert {item.rule_id for item in php} == {"asset-path-php", "cookie-phpsessid"}


def test_detects_common_application_servers_from_server_header():
    observations = detect_technologies({"server": "gunicorn/22.0.0"}, {}, [])
    assert any(item.product == "Gunicorn" and item.version == "22.0.0" for item in observations)


def test_extracts_library_version_from_asset_path():
    observations = detect_technologies({}, {}, ["https://example.com/js/jquery-3.7.1.min.js"])
    assert any(item.product == "jQuery" and item.version == "3.7.1" for item in observations)


def test_uses_corroborating_framework_markers_from_cookies_and_html():
    observations = detect_technologies(
        {}, {}, [],
        [{"name": "connect.sid", "attributes": []}],
        html='<meta name="csrf-param" content="authenticity_token"><html ng-version="17.2.0">',
    )
    assert any(item.product == "Express" and item.rule_id == "cookie-connect-sid" for item in observations)
    assert any(item.product == "Ruby on Rails" for item in observations)
    assert any(item.product == "Angular" and item.version == "17.2.0" for item in observations)
