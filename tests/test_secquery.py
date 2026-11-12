import hashlib
import json
import os
import zipfile

import pytest
from cryptography.exceptions import InvalidTag

from secquery.database import SignatureDB
from secquery.cli import main
from secquery.quarantine import quarantine_file, restore_file
from secquery.scanner import scan_file, walk_files


def test_hashing_and_local_signature_match(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"x" * 100)
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    md5 = hashlib.md5(sample.read_bytes(), usedforsecurity=False).hexdigest()
    with SignatureDB(tmp_path / "db.sqlite") as db:
        db.add(digest, md5, "Fixture signature", "critical")
        db.conn.commit()
        result = scan_file(sample, db)
    assert result.sha256 == digest
    assert result.md5 == md5
    assert result.status == "threat"
    assert any(f.rule == "known_hash" for f in result.findings)


def test_script_detection_and_explainable_risk(tmp_path):
    sample = tmp_path / "run.ps1"
    sample.write_text("powershell DownloadString", encoding="utf-8")
    result = scan_file(sample)
    assert {f.rule for f in result.findings} >= {"powershell_download_cradle"}
    assert result.risk_score > 0


def test_static_pe_section_analysis_and_entropy(tmp_path):
    data = bytearray(1536)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional:optional + 2] = (0x10B).to_bytes(2, "little")
    section = optional + 0xE0
    data[section:section + 5] = b".text"
    data[section + 16:section + 20] = (1024).to_bytes(4, "little")
    data[section + 20:section + 24] = (512).to_bytes(4, "little")
    data[section + 36:section + 40] = (0xA0000000).to_bytes(4, "little")
    data[512:] = bytes(range(256)) * 4
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(data)
    result = scan_file(sample)
    rules = {finding.rule for finding in result.findings}
    assert "pe_writable_executable_section" in rules
    assert "high_entropy_pe_section" in rules


def test_malformed_elf_is_explained(tmp_path):
    sample = tmp_path / "bad-elf"
    sample.write_bytes(b"\x7fELF\x02\x01")
    result = scan_file(sample)
    assert any(f.rule == "malformed_elf_header" for f in result.findings)


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("safe")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    assert list(walk_files([tmp_path])) == [(target, None)]
    assert scan_file(link).status == "error"


def test_symlinked_parent_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    target = real / "target.txt"
    target.write_text("safe")
    linkdir = tmp_path / "linked-dir"
    try:
        linkdir.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    assert scan_file(linkdir / "target.txt").status == "error"


def test_zip_member_inspection_without_extraction(tmp_path):
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested/run.ps1", "DownloadString powershell")
    result = scan_file(archive)
    assert any(f.rule == "powershell_download_cradle" for f in result.findings)
    assert not (tmp_path / "nested").exists()


def test_signature_pack_roundtrip_and_validation(tmp_path):
    digest = "a" * 64
    with SignatureDB(tmp_path / "one.sqlite") as db:
        db.add(digest, "b" * 32, "sample")
        db.conn.commit()
        pack = tmp_path / "signatures.json"
        assert db.export_pack(pack) == 1
    with SignatureDB(tmp_path / "two.sqlite") as db:
        assert db.import_pack(pack) == 1
        assert db.lookup(digest, "") == [("sample", "high", "local-pack")]
        broken = tmp_path / "broken.json"
        broken.write_text(json.dumps({"format": "bvdu-secquery-signatures", "version": 1,
                                      "signatures": [{"sha256": "nope"}]}))
        with pytest.raises(ValueError):
            db.import_pack(broken)


def test_quarantine_roundtrip_integrity_and_no_overwrite(tmp_path):
    source = tmp_path / "payload.bin"
    data = os.urandom(4096)
    source.write_bytes(data)
    entry = quarantine_file(source, tmp_path / "vault", "correct horse battery staple")
    assert entry.read_bytes()[:6] == b"BVDQ1\x00"
    assert not source.exists()
    restored = tmp_path / "restored.bin"
    digest = restore_file(entry, restored, "correct horse battery staple")
    assert restored.read_bytes() == data
    assert digest == hashlib.sha256(data).hexdigest()
    with pytest.raises(FileExistsError):
        restore_file(entry, restored, "correct horse battery staple")
    with pytest.raises(InvalidTag):
        restore_file(entry, tmp_path / "wrong.bin", "wrong passphrase definitely")


def test_quarantine_refuses_short_passphrase(tmp_path):
    source = tmp_path / "payload"
    source.write_bytes(b"contents")
    with pytest.raises(ValueError):
        quarantine_file(source, tmp_path / "vault", "short")


def test_cli_json_report_is_machine_readable(tmp_path, capsys):
    sample = tmp_path / "plain.txt"
    sample.write_text("ordinary notes", encoding="utf-8")
    result = main(["scan", str(sample), "--db", str(tmp_path / "cli.sqlite"), "--format", "json", "--no-sync"])
    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["results"][0]["status"] == "clean"


def test_no_argument_launch_starts_automatic_scan(tmp_path, monkeypatch):
    import sys
    from secquery import cli

    captured = {}
    monkeypatch.setattr(sys, "argv", ["secquery"])
    monkeypatch.setattr(cli, "_default_scan_paths", lambda: [tmp_path])

    def fake_scan(args):
        captured["paths"] = args.paths
        return 0

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main() == 0
    assert captured["paths"] == [str(tmp_path)]


def test_file_walk_limit_is_explicit_and_stops(tmp_path):
    for name in ("one.txt", "two.txt", "three.txt"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    results = list(walk_files([tmp_path], max_files=2))
    assert sum(path is not None for path, _ in results) == 2
    assert any("2 file safety limit" in error for _, error in results if error)


def test_text_scan_reports_progress_in_bounded_batches(tmp_path, capsys):
    target = tmp_path / "many"
    target.mkdir()
    for index in range(205):
        (target / f"{index:03}.txt").write_text("ordinary text", encoding="utf-8")
    result = main(["scan", str(target), "--db", str(tmp_path / "stream.sqlite"),
                   "--format", "text", "--no-sync"])
    output = capsys.readouterr().out
    assert result == 0
    assert "Progress: scanned 100 file(s)" in output
    assert "Progress: scanned 200 file(s)" in output
    assert "Scanned 205 file(s)" in output


def test_directory_scan_skips_per_file_native_processes_by_default(tmp_path, capsys, monkeypatch):
    from secquery import cli
    from secquery.engines import CompositeScanner, SyncReport

    target = tmp_path / "folder"
    target.mkdir()
    (target / "plain.txt").write_text("ordinary text", encoding="utf-8")

    class MustNotRun:
        def scan(self, _path):
            raise AssertionError("native process must be skipped for directory scans by default")

    report = SyncReport()
    report.sources.append({"name": "ClamAV", "status": "synced", "message": "updated"})
    engine = CompositeScanner([("ClamAV", MustNotRun())])
    monkeypatch.setattr(cli, "sync_all", lambda *_args, **_kwargs: (report, engine))
    assert main(["scan", str(target), "--db", str(tmp_path / "bulk.sqlite"), "--no-sync"]) == 0
    assert "Skipped per-file ClamAV subprocess scans" in capsys.readouterr().out


