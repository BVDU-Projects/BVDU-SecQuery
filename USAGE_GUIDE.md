# BVDU-SecQuery: usage guide

This guide walks through setup, online signature refresh, offline scanning, reports, and quarantine on Windows 10/11, Linux, and macOS.

## 1. Install

Install Python 3.10 or newer. From PowerShell in the project folder:

```powershell
.\install.ps1
.\.venv\Scripts\secquery.exe --help
```

Linux/macOS:

```sh
sh ./install.sh
./.venv/bin/secquery --help
```

The installer sets up SecQuery and tries to add YARA as an optional detection layer. If YARA cannot be installed on your platform, SecQuery continues with its built-in static checks and any available antivirus engine.

## 2. Add a free antivirus signature engine

SecQuery does not bundle a malware database. For a free, frequently updated signature engine, install ClamAV from the [official installation guide](https://docs.clamav.net/manual/Installing.html). Install the command-line scanner and FreshClam updater, then ensure `clamscan` and `freshclam` are available in `PATH` (Windows installers commonly use `C:\Program Files\ClamAV`). SecQuery then downloads and verifies ClamAV's signed definitions during online scans and uses cached definitions when offline.

On Windows, SecQuery also checks whether Microsoft Defender Antivirus is enabled in active (`Normal`) mode. If it is, SecQuery requests a signature update and runs a custom scan for each file. The custom scan disables remediation, so SecQuery does not instruct Defender to delete or quarantine files. If another antivirus is active, Defender is passive, or its state cannot be confirmed, SecQuery leaves Defender alone. Keep the active antivirus enabled; SecQuery is an additional on-demand tool.

## 3. Scan online or offline

An ordinary scan first attempts to update available signature sources, then scans locally. Network problems do not stop the local scan:

```powershell
secquery scan "$env:USERPROFILE\Downloads"
```

From a source checkout without installing, replace `secquery` with `python -m secquery.cli`.

### Start without typing a command

On Windows, double-click `Start-SecQuery.cmd`. It starts a scan of all fixed drives, displays status and progress in the open terminal, and waits when finished so the result stays visible. You can also run `secquery` without arguments in a terminal to start the same automatic scan. On Linux/macOS, no-argument startup scans the current user's home folder. The Windows scan runs at below-normal process priority and the traversal safety cap is 100,000 files; a full system scan may take a long time. Press Ctrl+C to cancel and return to the prompt.

Directory and whole-drive scans update the available signature sources but do not start a separate ClamAV/Defender process for every file. They use local hashes and static/YARA inspection while the computer's active antivirus continues its normal real-time protection. This avoids the process overhead that made large scans unresponsive. For a small directory where you want per-file antivirus subprocess scans, explicitly add `--native-per-file`; expect it to run more slowly.

To force offline operation, including no hash lookups or signature updates:

```powershell
secquery scan .\sample.exe --no-sync
```

Offline scanning uses your local SQLite hash database, cached ClamAV definitions (if installed), YARA (if installed), static file and script inspection, and bounded archive inspection. Results reflect the signatures present on this device; offline mode cannot learn about threats discovered after your last update.

## 4. Understand online sources and privacy

- **ClamAV/FreshClam:** free, signed antivirus definitions. Requires a separate ClamAV installation. When available, it is the primary no-key threat-signature source.
- **Microsoft Defender:** on Windows only, and only when the system reports Defender as active. SecQuery may request an update before scanning.
- **ThreatFox:** optional free file-hash indicators. It requires a free abuse.ch Auth-Key. Set `SECQUERY_THREATFOX_AUTH_KEY` in your shell to enable it; the key is sent only to ThreatFox over HTTPS.
- **CIRCL hashlookup:** free, keyless known-file metadata. After scanning, SecQuery can send bounded batches of MD5 fingerprints to identify entries in reference collections. It sends no file bytes, names, paths, or contents. A match is descriptive context, not a maliciousness verdict. Use `--no-sync` to stop these requests too.

Providers can be unavailable, limited, or stale. Check the sync status in the report. SecQuery does not call paid services and does not upload samples. A clean result is not proof that a file is safe.

## 5. Scan options and reports

```text
secquery scan PATH [PATH ...] [--format text|json|csv] [--output FILE]
                    [--no-sync] [--no-archives] [--quarantine-dir DIR]
secquery sync [--offline]
secquery signatures init
secquery signatures import PACK.json
secquery signatures export PACK.json
secquery restore ENTRY.bvdq DESTINATION
```

Example machine-readable report:

```powershell
secquery scan .\Downloads --format json --output .\scan-report.json
```

Risk points and evidence are shown per finding. Totals cap at 100; score bands are triage guidance, not calibrated infection probabilities. Exit codes: `0` no high-risk results and no scan errors; `1` one or more high-risk results; `2` traversal/scan errors or invalid operation. Review JSON/CSV `warnings` and `engines` fields for incomplete engine coverage.

Traversal skips symbolic links and Windows reparse points, ignores special files, caps the walk at 100,000 files, and never extracts ZIP entries. ZIP inspection has archive, member-count, and decompressed-member limits. Hashing is streamed; content analysis uses a bounded sample. These protections reduce risk but cannot guarantee that every malformed file or archive is understood.

## 6. Import/export local signatures

Signature packs can be shared through your project or imported from a source you trust:

```powershell
secquery signatures import .\trusted-signatures.json
secquery signatures export .\local-signatures.json
```

Packs are not signed by SecQuery. Verify their provenance before importing. The built-in database starts empty and stores local hash matches and cached known-file metadata under the current user's application data directory. Set `SECQUERY_DB` to use a different SQLite file.

## 7. Quarantine and restore

Quarantine is opt-in and applies to files scored high risk (50+):

```powershell
secquery scan .\suspect --quarantine-dir .\vault
secquery restore .\vault\ENTRY.bvdq .\restored\sample.bin
```

Use a passphrase of at least 12 characters. SecQuery derives an AES-256-GCM key with scrypt, authenticates each encrypted entry, and verifies the original SHA-256 on restore. Restore refuses to overwrite an existing destination. The original is removed after a verified vault write; this is not secure erasure, and backups or storage snapshots may retain copies. Keep the passphrase safe: it cannot be recovered. Do not restore a suspicious file to an auto-launch location.

## 8. Known limits

SecQuery is an educational/community on-demand scanner, not a replacement for Microsoft Defender or another real-time antivirus product. It has no behavioral sandbox, kernel monitoring, exploit prevention, or exhaustive format parser. Static heuristics can miss packed, encrypted, novel, or disguised threats and can flag legitimate administrative scripts. Signature freshness depends on the available providers and internet access. Use Windows Security or your platform's built-in protections alongside SecQuery.

## Useful references

- [ClamAV signature management](https://docs.clamav.net/manual/Usage/SignatureManagement.html)
- [ClamAV installation](https://docs.clamav.net/manual/Installing.html)
- [Microsoft Defender command-line scans and signature updates](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [CIRCL hashlookup service](https://www.circl.lu/services/hashlookup/)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
