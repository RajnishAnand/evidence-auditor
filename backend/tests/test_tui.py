from backend.app.scanning.schemas import ScanResult, ScanStatus
from backend.app.tui import _result_lines, display_result


def test_display_result_includes_status_and_evidence():
    lines: list[str] = []
    display_result(
        ScanResult(
            target="https://example.com",
            status=ScanStatus.completed,
            http_status=200,
            headers={"server": "example"},
        ),
        lines.append,
    )
    rendered = "\n".join(lines)
    assert "Status       completed" in rendered
    assert "RESPONSE HEADERS" in rendered
    assert "server: example" in rendered
    assert "VULNERABILITY CANDIDATES" in rendered


def test_result_lines_wrap_long_values_for_narrow_terminals():
    result = ScanResult(
        target="https://example.com",
        status=ScanStatus.completed,
        headers={"x-long-header": "a" * 120},
    )

    lines = _result_lines(result, width=40)

    assert any(len(line) <= 40 for line in lines)
    assert "x-long-header:" in "\n".join(lines)
