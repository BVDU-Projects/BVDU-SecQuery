"""Command line interface for BVDU-SecQuery."""
import argparse
import csv
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__
from .database import SignatureDB
from .engines import (HASHLOOKUP_BATCH_SIZE, MAX_HASHLOOKUP_BATCHES, SyncReport,
                      enrich_known_files, sync_all)
from .quarantine import quarantine_file, restore_file
from .scanner import FILE_COUNT_LIMIT, scan_file, walk_files, yara_available


def _console():
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def _print(text: str, *, style: str = ""):
    console = _console()
    if console:
        console.print(text, style=style)
    else:
        print(text)


def _write_report(results: list[dict], fmt: str, output: str | None,
                  sync_report: SyncReport | None = None):
    stream = open(output, "w", newline="", encoding="utf-8") if output else sys.stdout
    try:
        if fmt == "text":
            for result in results:
                stream.write(f"{result['status'].upper()} {result['risk_score']}/100 {result['path']}\n")
                for finding in result["findings"]:
                    stream.write(f"  [{finding['severity']}] {finding['rule']}: {finding['description']}\n")
                for error in result["errors"]:
                    stream.write(f"  ERROR: {error}\n")
        elif fmt == "json":
            json.dump({"product": "BVDU-SecQuery", "version": __version__,
                       "sync": sync_report.to_dict() if sync_report else None,
                       "results": results}, stream, indent=2)
            stream.write("\n")
        else:
            fields = ["path", "status", "sha256", "md5", "size", "file_type", "risk_score",
                      "risk_level", "findings", "errors", "warnings", "engines", "scanned_at",
                      "intel", "quarantined_to", "sync_status"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for result in results:
                row = dict(result)
                row["findings"] = json.dumps(row["findings"], ensure_ascii=False)
                row["errors"] = json.dumps(row["errors"], ensure_ascii=False)
                row["warnings"] = json.dumps(row["warnings"], ensure_ascii=False)
                row["engines"] = json.dumps(row["engines"], ensure_ascii=False)
                row["intel"] = json.dumps(row["intel"], ensure_ascii=False)
                row["sync_status"] = sync_report.status if sync_report else "unknown"
                writer.writerow(row)
    finally:
        if output:
            stream.close()


def _password(confirm: bool = False) -> str:
    try:
        first = getpass.getpass("Vault passphrase (minimum 12 characters): ")
        if confirm and first != getpass.getpass("Confirm passphrase: "):
            raise ValueError("Passphrases did not match")
        return first
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError("Passphrase input cancelled") from exc


def _scan(args) -> int:
    if args.max_files < 1:
        _print("--max-files must be at least 1.", style="red")
        return 2
    if not yara_available():
        print("YARA rules are unavailable; install the optional 'yara' extra to enable them.", file=sys.stderr)
    if args.format == "text":
        _print("Preparing scan and checking available signature updates...", style="cyan")
    keep_results = args.format != "text" or bool(args.output)
    results = []
    quarantine_targets = []
    lookup_reports = []
    lookup_remaining = MAX_HASHLOOKUP_BATCHES * HASHLOOKUP_BATCH_SIZE
    threat_count = 0
    file_error_count = 0
    with SignatureDB(args.db) as db:
        sync_report, clamav = sync_all(db, network=not args.no_sync)
    paths = [Path(p).expanduser() for p in args.paths]
    bulk_scan = len(paths) > 1 or any(path.is_dir() for path in paths)
    if bulk_scan and clamav and not args.native_per_file:
        names = ", ".join(name for name, _scanner in clamav.scanners)
        warning = (f"Skipped per-file {names} subprocess scans for this directory/full-drive scan to avoid "
                   "restarting an antivirus process for every file. Local hash, YARA/static checks, and the "
                   "operating system's active real-time protection still apply. Use --native-per-file only "
                   "for smaller scans if you accept the extra time and load.")
        sync_report.warnings.append(warning)
        for source in sync_report.sources:
            if source.get("name") in {name for name, _scanner in clamav.scanners}:
                source["scan_mode"] = "skipped-for-bulk"
        if args.format == "text":
            _print(warning, style="yellow")
        clamav = None
    walk_errors = []
    walk_error_count = 0
    WALK_ERROR_DETAIL_LIMIT = 100
    scanned_count = 0
    # Keep the scanner responsive while a user-initiated full-disk scan runs on Windows.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)
        except (AttributeError, OSError):
            pass
    if args.format == "text":
        _print(f"Starting scan of {len(paths)} location(s). Progress is reported every 100 files.", style="cyan")
        _print(f"Signature sync: {sync_report.status}", style="cyan")
        for source in sync_report.sources:
            _print(f"  {source['name']}: {source['message']}")
    with SignatureDB(args.db) as db:
        for path, error in walk_files(paths, max_files=args.max_files):
            if error:
                walk_error_count += 1
                if len(walk_errors) < WALK_ERROR_DETAIL_LIMIT:
                    walk_errors.append(error)
                    sync_report.warnings.append(f"Traversal: {error}")
                if args.format == "text" and walk_error_count <= 25:
                    _print(f"Traversal warning: {error}", style="yellow")
                continue
            if path is None:
                continue
            scanned_count += 1
            result = scan_file(path, db, archive=not args.no_archives, clamav=clamav)
            result_data = result.to_dict()
            results.append(result_data)
            threat_count += result.status == "threat"
            file_error_count += result.status == "error"
            if args.quarantine_dir and result.status == "threat":
                quarantine_targets.append((path, result.sha256))
            if not keep_results and (len(results) >= 100):
                lookup_status = enrich_known_files(results, db,
                                                   enabled=not args.no_sync and lookup_remaining > 0)
                lookup_reports.append(lookup_status)
                lookup_remaining = max(0, lookup_remaining - lookup_status.get("checked", 0))
                if lookup_status["status"] in {"failed", "partial"}:
                    lookup_remaining = 0
                _show_progress_batch(results, scanned_count)
                results.clear()
        if keep_results:
            lookup_status = enrich_known_files(results, db, enabled=not args.no_sync)
        else:
            if results:
                lookup_status = enrich_known_files(results, db,
                                                   enabled=not args.no_sync and lookup_remaining > 0)
                lookup_reports.append(lookup_status)
                lookup_remaining = max(0, lookup_remaining - lookup_status.get("checked", 0))
                if lookup_status["status"] in {"failed", "partial"}:
                    lookup_remaining = 0
                _show_progress_batch(results, scanned_count)
                results.clear()
            lookup_status = _combine_lookup_reports(lookup_reports, not args.no_sync)
    if scanned_count == 0:
        for message in walk_errors or ["No regular files found."]:
            _print(message, style="yellow")
        return 2
    sync_report.sources.append(lookup_status)
    if args.format == "text":
        _print(f"  {lookup_status['name']}: {lookup_status['message']}")
    if lookup_status["status"] == "synced":
        if sync_report.status == "offline":
            sync_report.status = "partial"
        elif sync_report.status == "offline-fallback":
            sync_report.status = "partial"
    elif lookup_status["status"] in {"failed", "partial"}:
        sync_report.warnings.append(lookup_status["message"])
        if sync_report.status == "synced":
            sync_report.status = "partial"
    if args.format == "text":
        for result in results:
            # Per-file work was announced during scanning; print findings and any warning now.
            color = {"threat": "bold red", "suspicious": "yellow", "clean": "green", "error": "red"}.get(result["status"], "")
            if result["status"] not in {"clean", "threat"}:
                _print(f"{result['status'].upper():10} {result['risk_score']:3}/100  {result['path']}", style=color)
            for item in result["intel"]:
                _print(f"  · Known-file context: {item.get('file_name', '')} [{item.get('source_set', '')}]")
            for error in result["errors"]:
                _print(f"  ! {error}", style="red")
            for warning in result["warnings"]:
                _print(f"  ? {warning}", style="yellow")
    else:
        for warning in sync_report.warnings:
            print(f"Signature sync: {warning}", file=sys.stderr)
    if walk_error_count > len(walk_errors):
        omitted = walk_error_count - len(walk_errors)
        message = f"Omitted {omitted} additional traversal error details to keep the report bounded."
        sync_report.warnings.append(message)
        if args.format == "text":
            _print(message, style="yellow")
    if args.quarantine_dir:
        if quarantine_targets:
            phrase = _password(confirm=True)
            for path, digest in quarantine_targets:
                try:
                    entry = quarantine_file(path, args.quarantine_dir, phrase, digest)
                    if args.format == "text":
                        _print(f"Encrypted quarantine: {path.name} -> {entry}", style="bold yellow")
                except Exception as exc:
                    if args.format == "text":
                        _print(f"Quarantine failed for {path}: {exc}", style="red")
    if args.output:
        _write_report(results, args.format, args.output, sync_report)
        if args.format == "text":
            _print(f"Report written to {args.output}")
    elif args.format in {"json", "csv"}:
        _write_report(results, args.format, None, sync_report)
    error_count = file_error_count + walk_error_count
    if args.format == "text":
        _print(f"Scanned {scanned_count} file(s): {threat_count} high-risk, {error_count} error(s).")
    return 2 if error_count else 1 if threat_count else 0


def _show_progress_batch(results: list[dict], scanned_count: int) -> None:
    threats = sum(item["status"] == "threat" for item in results)
    errors = sum(item["status"] == "error" for item in results)
    _print(f"Progress: scanned {scanned_count} file(s); this batch: {threats} high-risk, {errors} error(s).",
           style="cyan")
    for result in results:
        if result["status"] not in {"threat", "suspicious", "error"}:
            continue
        _print(f"{result['status'].upper():10} {result['risk_score']:3}/100  {result['path']}")
        for finding in result["findings"]:
            _print(f"  - [{finding['severity']}] {finding['rule']}: {finding['description']}")
        for warning in result["warnings"]:
            _print(f"  ? {warning}", style="yellow")
        for error in result["errors"]:
            _print(f"  ! {error}", style="red")


def _combine_lookup_reports(reports: list[dict], enabled: bool) -> dict:
    if not reports:
        return {"name": "CIRCL hashlookup", "status": "skipped", "checked": 0,
                "matches": 0, "message": "No files were available for online hash context."}
    statuses = [item["status"] for item in reports]
    checked = sum(int(item.get("checked", 0)) for item in reports)
    matches = sum(int(item.get("matches", 0)) for item in reports)
    deferred = enabled and "skipped" in statuses and any(value in {"synced", "cached"} for value in statuses)
    if not enabled or all(status == "skipped" for status in statuses):
        status = "skipped"
    elif "failed" in statuses or "partial" in statuses:
        status = "partial" if any(value in {"synced", "cached"} for value in statuses) else "failed"
    elif deferred:
        status = "partial"
    elif "synced" in statuses:
        status = "synced"
    elif "cached" in statuses:
        status = "cached"
    else:
        status = "skipped"
    message = (f"Checked {checked} unique file hashes across bounded batches; {matches} matched known-file records. "
               "A match is context, not a malware verdict.")
    if deferred:
        message += " Some later hashes were not queried to keep network use bounded."
    return {"name": "CIRCL hashlookup", "status": status, "checked": checked,
            "matches": matches, "message": message}


def _build_parser():
    parser = argparse.ArgumentParser(prog="secquery", description="Offline-first cross-platform file scanner")
    parser.add_argument("--version", action="version", version=f"BVDU-SecQuery {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan files and directories")
    scan.add_argument("paths", nargs="+", help="Files or directories to scan")
    scan.add_argument("--db", help="SQLite signature database path")
    scan.add_argument("--format", choices=("text", "json", "csv"), default="text")
    scan.add_argument("--output", help="Write report to this path")
    scan.add_argument("--no-archives", action="store_true", help="Skip ZIP member inspection")
    scan.add_argument("--max-files", type=int, default=FILE_COUNT_LIMIT,
                      help=f"Stop safely after this many files (default: {FILE_COUNT_LIMIT})")
    scan.add_argument("--native-per-file", action="store_true",
                      help="Run installed antivirus subprocesses for every file in a directory; can be slow")
    scan.add_argument("--quarantine-dir", help="Encrypt high-risk files into this vault after review")
    scan.add_argument("--no-sync", "--offline", dest="no_sync", action="store_true",
                      help="Skip all network access and use cached offline intelligence")
    signatures = sub.add_parser("signatures", help="Manage offline signature packs")
    signatures.add_argument("action", choices=("init", "import", "export"))
    signatures.add_argument("file", nargs="?", help="Input/output JSON or CSV pack")
    signatures.add_argument("--db", help="SQLite signature database path")
    restore = sub.add_parser("restore", help="Decrypt a quarantine entry and verify integrity")
    restore.add_argument("entry", help="Encrypted .bvdq entry")
    restore.add_argument("destination", help="New destination path; existing files are never overwritten")
    restore.add_argument("--passphrase-stdin", action="store_true", help="Read passphrase from stdin")
    sync = sub.add_parser("sync", help="Update available antivirus signatures and optional threat feeds")
    sync.add_argument("--db", help="SQLite signature database path")
    sync.add_argument("--offline", action="store_true", help="Check cached sources without connecting")
    return parser


def _default_scan_paths() -> list[Path]:
    """Choose fixed Windows volumes, or the home directory on Unix-like systems."""
    if os.name != "nt":
        return [Path.home()]
    try:
        import ctypes
        drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
        paths = []
        for index in range(26):
            if not drive_mask & (1 << index):
                continue
            root = f"{chr(ord('A') + index)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
                paths.append(Path(root))
        if paths:
            return paths
    except (AttributeError, OSError):
        pass
    return [Path(os.environ.get("SystemDrive", "C:") + "\\")]


def main(argv=None) -> int:
    auto_scan = argv is None and len(sys.argv) == 1
    if auto_scan:
        paths = _default_scan_paths()
        if os.name == "nt":
            _print("No command was supplied. Starting an automatic scan of fixed Windows drives.", style="cyan")
        else:
            _print("No command was supplied. Starting an automatic scan of your home directory.", style="cyan")
        argv = ["scan", *(str(path) for path in paths)]
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "signatures":
            with SignatureDB(args.db) as db:
                if args.action == "init":
                    _print(f"Signature database ready: {db.path}")
                elif not args.file:
                    raise ValueError(f"signatures {args.action} requires a file")
                elif args.action == "import":
                    _print(f"Imported {db.import_pack(args.file)} signature(s).")
                elif args.action == "export":
                    _print(f"Exported {db.export_pack(args.file)} signature(s).")
            return 0
        if args.command == "sync":
            with SignatureDB(args.db) as db:
                report, _ = sync_all(db, network=not args.offline)
            _print(f"Signature sync: {report.status}")
            for source in report.sources:
                _print(f"{source['name']}: {source['message']}")
            return 0 if report.status in {"synced", "partial", "offline", "offline-fallback"} else 2
        if args.command == "restore":
            phrase = sys.stdin.readline().rstrip("\r\n") if args.passphrase_stdin else _password()
            digest = restore_file(args.entry, args.destination, phrase)
            _print(f"Restored and verified SHA-256 {digest} -> {args.destination}", style="green")
            return 0
    except KeyboardInterrupt:
        _print("Scan cancelled by user. Any completed results remain valid.", style="yellow")
        return 130
    except Exception as exc:
        _print(f"Error: {exc}", style="red")
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
