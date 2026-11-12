import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from secquery import engines
from secquery.database import SignatureDB


def test_no_clamav_is_reported_and_offline_fallback_remains(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("SECQUERY_THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.setattr(engines, "_find_tool", lambda name: None)
    with SignatureDB(tmp_path / "hashes.sqlite") as db:
        report, scanner = engines.sync_all(db)
        assert report.status == "offline"
        assert scanner is None
        assert "ClamAV is not installed" in report.warnings[0]


def test_freshclam_sync_uses_managed_database_and_keeps_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(engines, "_find_tool", lambda name: f"C:/tools/{name}.exe")

    def run(argv, **kwargs):
        engines.clamav_database_dir().mkdir(parents=True, exist_ok=True)
        (engines.clamav_database_dir() / "daily.cvd").write_bytes(b"signed-db-fixture")
        return SimpleNamespace(returncode=0, stdout="up-to-date", stderr="")

    with patch.object(engines.subprocess, "run", side_effect=run) as mocked:
        source, scanner = engines.sync_clamav()
    assert source["status"] == "synced"
    assert source["database_ready"] is True
    assert scanner is not None
    assert mocked.call_args.kwargs["shell"] is False
    config_arg = mocked.call_args.args[0][1]
    config = Path(config_arg.split("=", 1)[1])
    assert "DatabaseMirror database.clamav.net" in config.read_text(encoding="utf-8")


def test_freshclam_failure_uses_signed_database_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    database = engines.clamav_database_dir()
    database.mkdir(parents=True)
    (database / "daily.cvd").write_bytes(b"cached-db")
    monkeypatch.setattr(engines, "_find_tool", lambda name: f"C:/tools/{name}.exe")
    failed = SimpleNamespace(returncode=1, stdout="network unreachable", stderr="")
    with patch.object(engines.subprocess, "run", return_value=failed):
        source, scanner = engines.sync_clamav()
    assert source["status"] == "offline-fallback"
    assert source["database_ready"] is True
    assert scanner is not None
    assert "network unreachable" in source["message"]


def test_clamscan_detection_does_not_request_remediation(tmp_path):
    scanner = engines.ClamAVScanner("clamscan", tmp_path)
    completed = SimpleNamespace(returncode=1, stdout="sample.exe: Win.Test FOUND", stderr="")
    with patch.object(engines.subprocess, "run", return_value=completed) as mocked:
        finding, warning = scanner.scan(tmp_path / "sample.exe")
    assert finding is not None and finding.rule == "clamav_signature"
    assert warning is None
    args = mocked.call_args.args[0]
    assert "--remove" not in args
    assert mocked.call_args.kwargs["shell"] is False


def test_threatfox_imports_only_valid_file_hashes(tmp_path, monkeypatch):
    monkeypatch.setenv("SECQUERY_THREATFOX_AUTH_KEY", "test-key")
    body = json.dumps({"query_status": "ok", "data": [
        {"ioc_type": "sha256_hash", "ioc": "a" * 64, "malware": "Example", "id": 10},
        {"ioc_type": "md5_hash", "ioc": "b" * 32, "malware": "Example", "id": 11},
        {"ioc_type": "ip:port", "ioc": "203.0.113.10:443", "malware": "Example", "id": 12},
        {"ioc_type": "sha256_hash", "ioc": "invalid", "malware": "bad", "id": 13},
    ]}).encode()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return body

    with patch.object(engines.urllib.request, "urlopen", return_value=Response()) as request:
        with SignatureDB(tmp_path / "hashes.sqlite") as db:
            report = engines.sync_threatfox(db)
            assert db.lookup("a" * 64, "") == [("ThreatFox Example IOC 10", "high", "ThreatFox")]
            assert db.lookup("", "b" * 32)[0][2] == "ThreatFox"
            assert db.signature_count() == 2
    assert report["status"] == "synced"
    assert report["imported"] == 2
    assert request.call_args.args[0].full_url == engines.THREATFOX_URL
    assert request.call_args.args[0].headers.get("Auth-key") == "test-key"


def test_expired_threatfox_ioc_is_ignored_and_local_record_is_preserved(tmp_path):
    sha = "d" * 64
    with SignatureDB(tmp_path / "hashes.sqlite") as db:
        db.add(sha, "", "temporary feed entry", source="ThreatFox")
        db.conn.execute("UPDATE signatures SET added_at=datetime('now', '-181 days') WHERE sha256=?", (sha,))
        db.conn.commit()
        assert db.lookup(sha, "") == []
        db.add(sha, "", "durable local entry", source="local-pack")
        assert db.add_many([{"sha256": sha, "name": "new feed label"}], source="ThreatFox") == 1
        assert db.lookup(sha, "") == [("durable local entry", "high", "local-pack")]


def test_hashlookup_adds_context_without_changing_risk(tmp_path):
    digest = "b" * 32
    results = [{"md5": digest, "risk_score": 0, "intel": []}]
    response_body = json.dumps([{"MD5": digest.upper(), "FileName": "known-tool.exe",
                                "db": "nsrl_modern_rds", "source": "NSRL"}]).encode()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return response_body

    with SignatureDB(tmp_path / "hashes.sqlite") as db:
        with patch.object(engines.urllib.request, "urlopen", return_value=Response()) as request:
            report = engines.enrich_known_files(results, db)
        assert engines.enrich_known_files(results, db)["status"] == "cached"
    assert report["status"] == "synced"
    assert results[0]["intel"][0]["file_name"] == "known-tool.exe"
    assert results[0]["risk_score"] == 0
    assert request.call_args.args[0].full_url == engines.HASHLOOKUP_URL
    assert digest.upper().encode() in request.call_args.args[0].data


def test_hashlookup_offline_mode_makes_no_request(tmp_path):
    results = [{"md5": "c" * 32, "intel": []}]
    with SignatureDB(tmp_path / "hashes.sqlite") as db:
        with patch.object(engines.urllib.request, "urlopen") as request:
            status = engines.enrich_known_files(results, db, enabled=False)
    request.assert_not_called()
    assert status["status"] == "skipped"


def test_failed_clamav_scan_is_warning_not_false_clean(tmp_path):
    class BrokenScanner:
        def scan(self, _path):
            return None, "database unavailable"

    sample = tmp_path / "note.txt"
    sample.write_text("ordinary text", encoding="utf-8")
    from secquery.scanner import scan_file

    result = scan_file(sample, clamav=BrokenScanner())
    assert result.status == "clean"
    assert "database unavailable" in result.warnings[0]
    assert "ClamAV" in result.engines


def test_defender_only_updates_when_windows_reports_active(tmp_path, monkeypatch):
    monkeypatch.setattr(engines.os, "name", "nt")
    monkeypatch.setattr(engines.shutil, "which", lambda name: "powershell.exe" if name == "powershell.exe" else None)
    monkeypatch.setattr(engines, "_find_defender_tool", lambda: "MpCmdRun.exe")
    status = SimpleNamespace(returncode=0, stdout='{"AntivirusEnabled":false,"AMRunningMode":"Passive"}', stderr="")
    with patch.object(engines.subprocess, "run", return_value=status) as mocked:
        report, scanner = engines.sync_windows_defender()
    assert scanner is None
    assert report["status"] == "inactive"
    assert "left untouched" in report["message"]
    assert mocked.call_count == 1


def test_active_defender_updates_and_scans_read_only(tmp_path, monkeypatch):
    monkeypatch.setattr(engines.os, "name", "nt")
    monkeypatch.setattr(engines.shutil, "which", lambda name: "powershell.exe" if name == "powershell.exe" else None)
    monkeypatch.setattr(engines, "_find_defender_tool", lambda: "MpCmdRun.exe")
    status = SimpleNamespace(returncode=0, stdout='{"AntivirusEnabled":true,"AMRunningMode":"Normal"}', stderr="")
    updated = SimpleNamespace(returncode=0, stdout="updated", stderr="")
    with patch.object(engines.subprocess, "run", side_effect=[status, updated]) as mocked:
        report, scanner = engines.sync_windows_defender()
    assert report["status"] == "synced"
    assert scanner is not None
    assert mocked.call_args_list[1].args[0] == ["MpCmdRun.exe", "-SignatureUpdate"]

    detected = SimpleNamespace(returncode=2, stdout="Threat detected: Test.Malware", stderr="")
    with patch.object(engines.subprocess, "run", return_value=detected) as scan_mock:
        finding, warning = scanner.scan(tmp_path / "sample.exe")
    assert finding is not None and finding.rule == "windows_defender_detection"
    assert warning is None
    args = scan_mock.call_args.args[0]
    assert "-DisableRemediation" in args
    assert "-Remove" not in args
    assert scan_mock.call_args.kwargs["shell"] is False


def test_defender_ambiguous_return_code_is_warning_not_clean(tmp_path):
    scanner = engines.WindowsDefenderScanner("MpCmdRun.exe")
    with patch.object(engines.subprocess, "run",
                      return_value=SimpleNamespace(returncode=2, stdout="scan error", stderr="")):
        finding, warning = scanner.scan(tmp_path / "sample.exe")
    assert finding is None
    assert "incomplete or needs review" in warning
