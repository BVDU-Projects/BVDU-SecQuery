# BVDU-SecQuery

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

An offline-first, cross-platform file scanner for Windows 10/11, Linux, and macOS. It combines ClamAV's signed malware definitions and scan engine when installed, an optional ThreatFox hash feed, local SHA-256/MD5 matching, static inspection, optional YARA rules, explainable risk scoring, and an encrypted quarantine vault. It never uploads scanned files.

## Features

- Local SQLite SHA-256/MD5 signature matching and portable signature packs.
- ClamAV/FreshClam signed definitions and scanning when installed.
- Optional Microsoft Defender updates and read-only custom scans on Windows, only when Defender reports active protection.
- Free ThreatFox file-hash IOCs when a free abuse.ch Auth-Key is configured; keyless CIRCL known-file context lookups.
- Bounded static PE, ELF, Mach-O, script, and ZIP inspection with bundled optional YARA rules.
- Explainable findings, JSON/CSV reports, offline operation, and authenticated encrypted quarantine/restore.

## Project files

| File or folder | Purpose |
| --- | --- |
| `secquery/` | Scanner, CLI, SQLite database, engine adapters, quarantine, and bundled rules |
| `tests/` | Automated unit and safety tests |
| `.github/workflows/tests.yml` | Windows, Linux, and macOS continuous integration |
| `USAGE_GUIDE.md` | Setup and practical command walkthrough |
| `Start-SecQuery.cmd` | Windows double-click launcher; starts an automatic scan and keeps the window open |
| `CONTRIBUTING.md` | Development and contribution workflow |
| `AUTHORS.md`, `CONTRIBUTORS.md` | Project and collaborator credits |
| `SECURITY.md` | Vulnerability reporting guidance |
| `install.ps1`, `install.sh` | Platform setup scripts |

## What it can and cannot tell you

SecQuery is an on-demand scanner, not a replacement for the operating system's real-time protection. Keep Microsoft Defender or your existing antivirus enabled. SecQuery detects only what its enabled engines, local signature database, and static rules know how to recognize. Static rules can miss new, packed, encrypted, or carefully disguised malware and can flag legitimate administrative tools. A clean result does **not** prove a file is safe. The local hash database starts empty. ClamAV and ThreatFox are separate free community sources; no single database is complete.

Every online `scan` first attempts signature synchronization. FreshClam is used when ClamAV is installed; it downloads and verifies ClamAV's signed definition databases. On Windows, SecQuery checks whether Microsoft Defender reports active protection and, if so, requests a signature update and performs a custom scan with remediation disabled. SecQuery does not enable Defender or alter antivirus settings. If `SECQUERY_THREATFOX_AUTH_KEY` is set, SecQuery also imports recent file-hash IOCs over HTTPS. After the local scan, SecQuery sends MD5 hashes in bounded batches to CIRCL hashlookup for known-file context and caches answers for 30 days. These hash queries can reveal which files you have, although file contents and paths are never sent. Use `--no-sync` to prevent all network access for that scan. Hashlookup matches identify files in known-file collections; they do not mean a file is safe. If the network or an update source fails, SecQuery keeps cached signatures and continues offline. For stronger free malware coverage on all platforms, install ClamAV; its scanner and FreshClam updater provide the keyless signed feed. ThreatFox is an optional free feed that requires a free abuse.ch Auth-Key.

The bundled YARA rules are conservative examples, not a commercial antivirus engine. Install the optional `yara` extra to enable them. Without `yara-python`, built-in static checks, ClamAV, and local hash matching still work. PE, ELF, and Mach-O checks cover file identification and basic header sanity; this is not full disassembly or behavioral emulation.

## Install

Python 3.10 or newer is required. The install scripts create an isolated `.venv` and install open-source dependencies. ClamAV is a separate program and is not silently installed by SecQuery. Install it from your OS package manager or the [official ClamAV installer instructions](https://docs.clamav.net/manual/Installing.html). On Windows, ClamAV publishes a portable ZIP as well as an installer. The optional YARA package may require platform-specific build support; if that install fails, the scanner will continue without YARA.

```powershell
# Windows PowerShell
.\install.ps1
```

```sh
# Linux / macOS
sh ./install.sh
```

Manual install:

```sh
python -m pip install .[yara]
```

Run `secquery --help` for command help. When running from a source checkout before installing, use `python -m secquery.cli`.

## Scan

```sh
secquery scan ./Downloads
secquery scan ./sample.exe --format json --output report.json
secquery scan ./folder --format csv --output report.csv
secquery scan ./folder --no-archives
secquery scan ./folder --no-sync
secquery sync
```

On Windows, double-click `Start-SecQuery.cmd` to start an automatic scan of fixed drives without typing a command. Running `secquery` with no arguments has the same behavior; Linux/macOS scan the current user's home directory. The scan prints progress every 100 files, can be cancelled with Ctrl+C, and runs at below-normal process priority on Windows. Text-mode scans process results in batches of 100 to limit memory use. Traversal stops at the safety limit of 100,000 files and reports the limit instead of silently claiming a complete scan. A full system-drive scan can still take a long time.

For directory and full-drive scans, SecQuery updates available engine definitions but skips repeatedly launching ClamAV/Defender as separate processes for every file, since that can stall a computer. Those multi-file scans use SecQuery's local hashes and static/YARA checks alongside the operating system's active real-time protection. `--native-per-file` opts into per-file antivirus subprocesses for smaller targets, with extra time and system load.

Scanning follows no symbolic links and ignores non-regular files. ZIP archives are inspected without extracting their members; inspection has fixed compressed-size, member-count, and per-member decompression limits. The default traversal limit is 100,000 files. Errors and limits are reported rather than silently treated as clean. The scanner reads files in chunks for hashing and limits content-based analysis to an 8 MiB sample.

Online hash context is capped at 1,000 fresh hashes per scan, deduplicated within the scan, and cached for 30 days. If a scan has more, remaining hashes are deferred to later scans. This database contains known-file metadata (including the NSRL and OS package data), not malware verdicts. Attribution: [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/) data is provided under CC-BY. The `--no-sync` option disables FreshClam, ThreatFox, and hashlookup requests while retaining local caches and installed offline engines.

Risk scores add explainable points from matching rules and cap at 100: low (0–19), medium (20–49), high (50–79), and critical (80–100). A high-risk result exits with code 1; scan or traversal errors exit with code 2; otherwise the exit code is 0. These scores are triage guidance, not a probability of infection.

## Offline hash intelligence

The SQLite database is created automatically under `%LOCALAPPDATA%\BVDU-SecQuery\signatures.sqlite3` on Windows, `~/Library/Application Support/BVDU-SecQuery/signatures.sqlite3` on macOS, or `~/.local/share/BVDU-SecQuery/signatures.sqlite3` on Linux. Set `SECQUERY_DB` to choose another location. FreshClam's cached databases are stored alongside it in the `clamav/database` folder.

### Optional ThreatFox feed

ThreatFox requires an abuse.ch Auth-Key. The API key is free; request one through the [abuse.ch authentication portal](https://auth.abuse.ch/), then set it in the environment. SecQuery sends the key only to the official ThreatFox HTTPS endpoint and stores only validated SHA-256/MD5 indicators. It does not submit files or request malware samples.

```powershell
$env:SECQUERY_THREATFOX_AUTH_KEY = "your-free-auth-key"
secquery sync
```

```sh
export SECQUERY_THREATFOX_AUTH_KEY="your-free-auth-key"
secquery sync
```

Recent ThreatFox data is pruned after 180 days to limit stale matches. ClamAV remains the keyless malware-definition update source when its engine is installed. SecQuery does not use VirusTotal's public API as a substitute AV feed, and does not treat URLhaus' generated network feeds as file hashes.

```sh
secquery signatures init
secquery signatures import ./trusted-pack.json
secquery signatures import ./trusted-pack.csv
secquery signatures export ./local-pack.json
```

JSON packs use this shape:

```json
{
  "format": "bvdu-secquery-signatures",
  "version": 1,
  "signatures": [
    {"sha256": "<64 lowercase hex characters>", "md5": "<optional 32 hex characters>", "name": "Example", "severity": "high"}
  ]
}
```

CSV uses `sha256,md5,name,severity` headers. The database is empty by default. There is no bundled malware hash corpus because a static list would quickly become stale and its provenance could not be guaranteed here.

## Encrypted quarantine and restore

Quarantine is opt-in and applies to high-risk results (score 50+):

```sh
secquery scan ./suspect --quarantine-dir ./vault
secquery restore ./vault/<entry>.bvdq ./restored/sample.exe
```

SecQuery prompts for a passphrase (minimum 12 characters). A per-entry random salt and nonce feed scrypt key derivation and AES-256-GCM authenticated encryption. The encrypted payload includes an encrypted SHA-256 digest; restore verifies both the GCM authentication tag and the digest. Restores never overwrite an existing file. The original source is removed only after a completed encrypted vault entry has been written and verified. Removal prevents routine execution from its original path but is **not secure erasure**; storage devices, backups, and snapshots may retain data. Keep a separate secure backup of your passphrase: lost passphrases cannot be recovered. Vault entries contain no original path, so choose a destination when restoring.

Quarantine accepts regular files up to 256 MiB. The vault directory and files are restricted to the current user where supported by the OS; Windows uses the directory's inherited access controls. Use a vault in a directory protected by your account. Do not restore a file into a location where it will execute automatically.

For non-interactive restore, pass the passphrase through standard input with `--passphrase-stdin`; avoid command-line arguments or shell history for secrets:

```sh
printf '%s\n' "$SECQUERY_VAULT_PASSPHRASE" | secquery restore entry.bvdq restored.bin --passphrase-stdin
```

## Tests

```sh
python -m pip install -e '.[dev]'
python -m pytest
```

The tests cover local hash matching, static detections, PE/ELF inspection, symlink handling, bounded archive inspection without extraction, signature-pack validation, online-feed response validation, sync fallback, read-only ClamAV detections, and quarantine round-trip, integrity, and no-overwrite behavior.

## BVDU Projects

BVDU-SecQuery is part of the BVDU Projects series. See [AUTHORS.md](AUTHORS.md), [CONTRIBUTORS.md](CONTRIBUTORS.md), and [CONTRIBUTING.md](CONTRIBUTING.md) for credits and contribution guidance. The project is licensed under MIT; see [LICENSE](LICENSE).

## License

MIT. See [LICENSE](LICENSE).
