"""Network synchronization and native antivirus engine adapters.

Only signature metadata is requested by SecQuery. User files are never uploaded.
ClamAV signatures are fetched and verified by the user's installed FreshClam tool.
ThreatFox is optional and requires the user's free abuse.ch Auth-Key.
"""
from __future__ import annotations

import json
import os
import hashlib
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding
from .safety import assert_no_link_components, is_linklike

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
HASHLOOKUP_URL = "https://hashlookup.circl.lu/bulk/md5"
MAX_THREATFOX_RESPONSE = 16 * 1024 * 1024
MAX_HASHLOOKUP_BATCHES = 10
HASHLOOKUP_BATCH_SIZE = 100
CLAMAV_TIMEOUT_SECONDS = 180
DEFENDER_TIMEOUT_SECONDS = 120


def app_data_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "BVDU-SecQuery"


def clamav_database_dir() -> Path:
    return app_data_dir() / "clamav" / "database"


def _find_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    names = [name, f"{name}.exe"] if os.name == "nt" else [name]
    roots = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV",
             Path(r"C:\ClamAV")] if os.name == "nt" else []
    if sys.platform == "darwin":
        roots.extend([Path("/usr/local/clamav/bin"), Path("/opt/homebrew/bin")])
    for root in roots:
        for candidate_name in names:
            candidate = root / candidate_name
            if candidate.is_file():
                return str(candidate)
    return None


def _clamav_config_path() -> Path:
    return app_data_dir() / "clamav" / "freshclam.conf"


def _prepare_freshclam_config() -> Path:
    database = assert_no_link_components(clamav_database_dir())
    database.mkdir(parents=True, exist_ok=True)
    if is_linklike(database):
        raise ValueError("ClamAV database path cannot be a symlink or reparse point")
    config = _clamav_config_path()
    config.parent.mkdir(parents=True, exist_ok=True)
    assert_no_link_components(config.parent)
    content = (
        f"DatabaseDirectory {database.as_posix()}\n"
        "DatabaseMirror database.clamav.net\n"
        "Checks 12\n"
        "ConnectTimeout 15\n"
        "ReceiveTimeout 60\n"
        "ScriptedUpdates yes\n"
    )
    temporary = config.with_suffix(".conf.tmp")
    temporary.write_text(content, encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(config)
    return config


@dataclass
class SyncReport:
    status: str = "offline"
    sources: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    synced_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


def sync_clamav(*, update: bool = True) -> tuple[dict, str | None]:
    freshclam = _find_tool("freshclam")
    clamscan = _find_tool("clamscan")
    database = clamav_database_dir()
    db_files = list(database.glob("*.cvd")) + list(database.glob("*.cld")) if database.is_dir() else []
    db_ready = bool(db_files)
    if not freshclam and not clamscan:
        return ({"name": "ClamAV", "status": "unavailable", "database_ready": False,
                 "message": "ClamAV is not installed; continuing with SecQuery's local checks."}, None)
    update_status = "unavailable"
    message = "FreshClam was not found; using any cached ClamAV database."
    if freshclam and update:
        try:
            config = _prepare_freshclam_config()
            completed = subprocess.run(
                [freshclam, f"--config-file={config}", "--stdout", "--verbose"],
                capture_output=True, text=True, timeout=CLAMAV_TIMEOUT_SECONDS, check=False,
                shell=False,
            )
            output = (completed.stdout + "\n" + completed.stderr).strip()
            db_files = list(clamav_database_dir().glob("*.cvd")) + list(clamav_database_dir().glob("*.cld"))
            db_ready = bool(db_files)
            if completed.returncode == 0:
                update_status = "synced" if db_ready else "failed"
                message = "Official ClamAV signatures are current." if db_ready else "FreshClam exited successfully but no definition database was found."
            else:
                update_status = "offline-fallback" if db_ready else "failed"
                message = "FreshClam could not update; using cached ClamAV signatures." if db_ready else "FreshClam update failed and no cached database is available."
                if output:
                    message += " " + output[-800:]
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            update_status = "offline-fallback" if db_ready else "failed"
            message = f"FreshClam unavailable ({exc}); using cached signatures if present."
    elif freshclam and not update:
        update_status = "skipped"
        message = "Online sync was disabled; checking the cached ClamAV database."
    if clamscan and db_ready:
        engine = ClamAVScanner(clamscan, clamav_database_dir())
    else:
        engine = None
    latest = max((item.stat().st_mtime for item in db_files), default=None)
    if latest is not None:
        updated_at = datetime.fromtimestamp(latest, timezone.utc).isoformat()
        age_hours = max(0, int((datetime.now(timezone.utc).timestamp() - latest) / 3600))
        if age_hours > 168:
            message += f" Cached definitions are {age_hours // 24} days old."
    else:
        updated_at = None
        age_hours = None
    return ({"name": "ClamAV", "status": update_status, "database_ready": db_ready,
             "database_updated_at": updated_at, "database_age_hours": age_hours,
             "message": message, "scanner_available": bool(engine)}, engine)


class ClamAVScanner:
    """Read-only use of clamscan with a user-owned, signed FreshClam database."""

    def __init__(self, executable: str, database: Path):
        self.executable = executable
        self.database = database

    def scan(self, path: Path) -> tuple[Finding | None, str | None]:
        try:
            completed = subprocess.run(
                [self.executable, f"--database={self.database}", "--no-summary", "--infected",
                 "--stdout", "--max-filesize=256M", "--max-scansize=512M", str(path)],
                capture_output=True, text=True, timeout=120, check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, "ClamAV scan timed out; other scan layers still ran."
        except OSError as exc:
            return None, f"ClamAV could not start: {exc}"
        output = (completed.stdout + "\n" + completed.stderr).strip()
        if completed.returncode == 0:
            return None, None
        if completed.returncode == 1 and "FOUND" in output.upper():
            signature = output[-500:]
            return Finding("clamav_signature", "high", 70,
                           f"ClamAV detected a known threat: {signature}", "ClamAV signed definitions"), None
        return None, f"ClamAV scan was incomplete (exit {completed.returncode}): {output[-500:]}"


def _find_defender_tool() -> str | None:
    """Find the current Windows Defender platform tool without changing system settings."""
    if os.name != "nt":
        return None
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform_root = program_data / "Microsoft" / "Windows Defender" / "Platform"
    candidates = sorted(platform_root.glob("*/*/MpCmdRun.exe"), reverse=True) if platform_root.is_dir() else []
    candidates.extend([
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Defender" / "MpCmdRun.exe",
    ])
    return next((str(path) for path in candidates if path.is_file()), None)


class WindowsDefenderScanner:
    """Read-only custom scans through active Microsoft Defender Antivirus."""

    def __init__(self, executable: str):
        self.executable = executable

    def scan(self, path: Path) -> tuple[Finding | None, str | None]:
        try:
            completed = subprocess.run(
                [self.executable, "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                capture_output=True, text=True, timeout=DEFENDER_TIMEOUT_SECONDS,
                check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, "Windows Defender scan timed out; other scan layers still ran."
        except OSError as exc:
            return None, f"Windows Defender could not start: {exc}"
        output = (completed.stdout + "\n" + completed.stderr).strip()
        lowered = output.lower()
        if any(marker in lowered for marker in ("threat detected", "threat name:", "found threat", "threats found")):
            return Finding("windows_defender_detection", "high", 70,
                           f"Microsoft Defender reported a detection: {output[-500:]}",
                           "Microsoft Defender Antivirus definitions"), None
        if completed.returncode == 0:
            return None, None
        # Defender uses exit code 2 for malware not remediated, user action, and scan errors.
        # Never turn an ambiguous status into a clean result.
        return None, f"Windows Defender scan was incomplete or needs review (exit {completed.returncode}): {output[-500:]}"


class CompositeScanner:
    """Run available native engines and retain each engine's finding and warning."""

    def __init__(self, scanners):
        self.scanners = scanners

    def scan_many(self, path: Path) -> tuple[list[Finding], list[str], list[str]]:
        findings, warnings, names = [], [], []
        for name, scanner in self.scanners:
            names.append(name)
            finding, warning = scanner.scan(path)
            if finding:
                findings.append(finding)
            if warning:
                warnings.append(warning)
        return findings, warnings, names


def sync_windows_defender(*, update: bool = True) -> tuple[dict, WindowsDefenderScanner | None]:
    """Update and use Defender only when Microsoft reports it active in Normal mode."""
    if os.name != "nt":
        return ({"name": "Microsoft Defender", "status": "not-applicable",
                 "message": "Windows Defender is available only on Windows."}, None)
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return ({"name": "Microsoft Defender", "status": "unavailable",
                 "message": "PowerShell was not found; Defender status could not be checked."}, None)
    command = "Get-MpComputerStatus | Select-Object AntivirusEnabled,AMRunningMode | ConvertTo-Json -Compress"
    try:
        status_result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=15, check=False, shell=False,
        )
        if status_result.returncode:
            raise ValueError((status_result.stderr or "status query failed")[-400:])
        state = json.loads(status_result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        return ({"name": "Microsoft Defender", "status": "unavailable",
                 "message": f"Defender status could not be confirmed; it was not invoked ({exc})."}, None)
    if not state.get("AntivirusEnabled") or str(state.get("AMRunningMode", "")).lower() != "normal":
        mode = str(state.get("AMRunningMode", "unknown"))
        return ({"name": "Microsoft Defender", "status": "inactive",
                 "message": f"Defender is not the active antivirus (mode: {mode}); it was left untouched."}, None)
    executable = _find_defender_tool()
    if not executable:
        return ({"name": "Microsoft Defender", "status": "unavailable",
                 "message": "Defender is active but MpCmdRun.exe could not be found."}, None)
    scanner = WindowsDefenderScanner(executable)
    if not update:
        return ({"name": "Microsoft Defender", "status": "skipped",
                 "message": "Online sync was disabled; Defender's current local definitions are used."}, scanner)
    try:
        updated = subprocess.run([executable, "-SignatureUpdate"], capture_output=True, text=True,
                                 timeout=DEFENDER_TIMEOUT_SECONDS, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ({"name": "Microsoft Defender", "status": "offline-fallback",
                 "message": f"Defender signature update failed; current local definitions remain available ({exc})."}, scanner)
    if updated.returncode == 0:
        return ({"name": "Microsoft Defender", "status": "synced",
                 "message": "Defender signature update completed."}, scanner)
    detail = (updated.stdout + "\n" + updated.stderr).strip()[-400:]
    return ({"name": "Microsoft Defender", "status": "offline-fallback",
             "message": f"Defender signature update failed (exit {updated.returncode}); current definitions remain available. {detail}"}, scanner)


def _ssl_context():
    # Use the operating system's certificate store (including Windows trust roots).
    import truststore
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def sync_threatfox(db, *, enabled: bool = True) -> dict:
    if not enabled:
        return {"name": "ThreatFox", "status": "skipped", "imported": 0,
                "message": "Online sync was disabled; cached signature matches remain active."}
    key = os.environ.get("SECQUERY_THREATFOX_AUTH_KEY", "").strip()
    if not key:
        return {"name": "ThreatFox", "status": "not-configured", "imported": 0,
                "message": "Set SECQUERY_THREATFOX_AUTH_KEY to enable its free feed."}
    request = urllib.request.Request(
        THREATFOX_URL,
        data=json.dumps({"query": "get_iocs", "days": 1}).encode("utf-8"),
        headers={"Auth-Key": key, "Content-Type": "application/json",
                 "User-Agent": "BVDU-SecQuery/1.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=25, context=_ssl_context()) as response:
            payload = response.read(MAX_THREATFOX_RESPONSE + 1)
        if len(payload) > MAX_THREATFOX_RESPONSE:
            raise ValueError("ThreatFox response exceeds the 16 MiB safety limit")
        data = json.loads(payload)
        if not isinstance(data, dict) or data.get("query_status") not in {"ok", "no_result", "no_results"}:
            status = data.get("query_status", "invalid response") if isinstance(data, dict) else "invalid response"
            raise ValueError(f"ThreatFox returned {status}")
        rows = []
        for item in data.get("data") or []:
            if not isinstance(item, dict):
                continue
            kind = item.get("ioc_type")
            value = str(item.get("ioc", "")).lower().strip()
            if kind == "sha256_hash" and _is_hex(value, 64):
                rows.append({"sha256": value, "name": f"ThreatFox {item.get('malware', 'malware')} IOC {item.get('id', '')}", "severity": "high"})
            elif kind == "md5_hash" and _is_hex(value, 32):
                # MD5-only IOCs need a SHA key for our DB schema; derive a sentinel SHA key
                # that cannot match a file's actual SHA-256, while the indexed MD5 still does.
                sentinel = hashlib.sha256(("md5:" + value).encode("ascii")).hexdigest()
                rows.append({"sha256": sentinel, "md5": value,
                             "name": f"ThreatFox {item.get('malware', 'malware')} MD5 IOC {item.get('id', '')}",
                             "severity": "high"})
        imported = db.add_many(rows, source="ThreatFox")
        db.prune_source("ThreatFox", older_than_days=180)
        return {"name": "ThreatFox", "status": "synced", "imported": imported,
                "message": f"Imported {imported} recent file-hash indicators."}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"name": "ThreatFox", "status": "failed", "imported": 0,
                "message": f"ThreatFox update failed; cached local signatures remain available ({exc})."}


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(char in "0123456789abcdef" for char in value)


def enrich_known_files(results: list[dict], db, *, enabled: bool = True) -> dict:
    """Enrich file reports from CIRCL's free known-file database, without changing risk."""
    if not enabled:
        return {"name": "CIRCL hashlookup", "status": "skipped", "checked": 0,
                "matches": 0, "message": "Online hash lookups were disabled."}
    by_md5: dict[str, list[int]] = {}
    for index, result in enumerate(results):
        md5 = str(result.get("md5", "")).lower()
        if _is_hex(md5, 32):
            by_md5.setdefault(md5, []).append(index)
    uncached, records = [], {}
    for digest in by_md5:
        cached = db.known_file_cache_get(digest)
        if cached is None:
            uncached.append(digest)
        elif cached:
            records[digest] = cached
    pending = uncached[:MAX_HASHLOOKUP_BATCHES * HASHLOOKUP_BATCH_SIZE]
    skipped = max(0, len(uncached) - len(pending))
    completed_batches = 0
    completed_hashes = 0
    failure = ""
    for offset in range(0, len(pending), HASHLOOKUP_BATCH_SIZE):
        batch = pending[offset:offset + HASHLOOKUP_BATCH_SIZE]
        request = urllib.request.Request(
            HASHLOOKUP_URL,
            data=json.dumps({"hashes": [item.upper() for item in batch]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "BVDU-SecQuery/1.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=12, context=_ssl_context()) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise ValueError("Hashlookup response exceeds the 2 MiB limit")
            decoded = json.loads(payload)
            if not isinstance(decoded, list) or len(decoded) > len(batch):
                raise ValueError("Hashlookup returned an invalid response")
            batch_set = set(batch)
            found: dict[str, dict] = {}
            for item in decoded:
                if not isinstance(item, dict):
                    continue
                digest = str(item.get("MD5", "")).lower()
                if digest not in batch_set or not _is_hex(digest, 32):
                    continue
                found[digest] = {
                    "source": "CIRCL hashlookup",
                    "database": str(item.get("db", ""))[:80],
                    "file_name": str(item.get("FileName", ""))[:256],
                    "source_set": str(item.get("source", ""))[:100],
                }
            for digest in batch:
                metadata = found.get(digest)
                db.known_file_cache_set(digest, metadata)
                if metadata:
                    records[digest] = metadata
            completed_batches += 1
            completed_hashes += len(batch)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            failure = f"CIRCL lookup failed ({exc}); local results remain unchanged."
            break
    for digest, metadata in records.items():
        for index in by_md5[digest]:
            results[index].setdefault("intel", []).append(metadata)
    checked = len(by_md5) - len(uncached) + completed_hashes
    matches = len(records)
    if failure and completed_batches:
        status = "partial"
    elif failure:
        status = "failed"
    elif pending:
        status = "synced"
    else:
        status = "cached" if by_md5 else "skipped"
    message = (f"Checked {checked} unique file hashes; {matches} matched known-file records. "
               "A match is context, not a malware verdict.")
    if failure:
        message += " " + failure
    if skipped:
        message += f" Deferred {skipped} hashes to keep public-feed requests bounded."
        if status == "synced":
            status = "partial"
    return {"name": "CIRCL hashlookup", "status": status, "checked": checked,
            "matches": matches, "message": message}


def sync_all(db, *, network: bool = True) -> tuple[SyncReport, CompositeScanner | None]:
    report = SyncReport()
    clamav, scanner = sync_clamav(update=network)
    report.sources.append(clamav)
    native_scanners = [("ClamAV", scanner)] if scanner else []
    if os.name == "nt":
        defender_source, defender = sync_windows_defender(update=network)
        report.sources.append(defender_source)
        if defender:
            native_scanners.append(("Microsoft Defender", defender))
    threatfox = sync_threatfox(db, enabled=network)
    report.sources.append(threatfox)
    successes = sum(source["status"] == "synced" for source in report.sources)
    attempted = sum(source["status"] in {"synced", "failed", "offline-fallback"} for source in report.sources)
    if successes:
        report.status = "synced" if successes == len([s for s in report.sources if s["status"] in {"synced", "failed", "offline-fallback"}]) else "partial"
    elif attempted:
        report.status = "offline-fallback" if any(s.get("database_ready") for s in report.sources) or db.signature_count() else "failed"
    else:
        report.status = "offline"
    for source in report.sources:
        if source["status"] in {"failed", "unavailable", "offline-fallback", "not-configured"}:
            report.warnings.append(source["message"])
    return report, CompositeScanner(native_scanners) if native_scanners else None
