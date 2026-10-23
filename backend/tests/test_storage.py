from backend.app.scanning.schemas import Evidence, ScanResult, ScanStatus
from backend.app.storage import ScanStore


def test_scan_store_preserves_complete_result(tmp_path):
    store = ScanStore(tmp_path / "history.sqlite3")
    result = ScanResult(
        target="https://example.com",
        status=ScanStatus.completed,
        http_status=200,
        headers={"server": "example"},
        evidence=[Evidence(source="test", value="observed")],
    )

    scan_id = store.save(result)
    restored = store.recent()

    assert scan_id == 1
    assert restored[0].target == result.target
    assert restored[0].headers == result.headers
    assert restored[0].evidence[0].value == "observed"
