"""Conservative static inspection, bounded traversal, and archive inspection."""
import hashlib
import functools
import importlib.util
import math
import os
import stat
import zipfile
from pathlib import Path

from .models import Finding, ScanResult
from .safety import assert_no_link_components, is_linklike

SAMPLE_LIMIT = 8 * 1024 * 1024
FILE_COUNT_LIMIT = 100_000
DIRECTORY_COUNT_LIMIT = 100_000
ARCHIVE_SIZE_LIMIT = 100 * 1024 * 1024
ARCHIVE_MEMBER_LIMIT = 500
ARCHIVE_MEMBER_SIZE_LIMIT = 25 * 1024 * 1024
YARA_RULES = Path(__file__).parent / "rules" / "secquery.yar"

PATTERNS = [
    ("eicar_test_string", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "medium", 35,
     "Contains the industry-standard antivirus test string (not malware)."),
    ("powershell_encoded_command", b"-enc", "medium", 20,
     "Contains an encoded PowerShell command switch."),
    ("powershell_download_cradle", b"downloadstring", "high", 35,
     "Contains a PowerShell download-and-execute style API."),
    ("powershell_dynamic_execution", b"invoke-expression", "medium", 25,
     "Contains PowerShell dynamic command execution."),
    ("powershell_base64_decode", b"frombase64string", "medium", 20,
     "Contains a PowerShell/.NET Base64 decoding call."),
    ("javascript_dynamic_execution", b"wscript.shell", "medium", 20,
     "Contains a Windows script-host command execution object."),
    ("office_auto_macro", b"autoopen", "low", 10,
     "Contains an Office auto-run macro entry point; legitimate documents can contain it."),
    ("script_eval", b"eval(", "medium", 20, "Contains a dynamic evaluation call."),
    ("suspicious_shell_execution", b"/bin/sh -c", "medium", 20,
     "Contains a shell command execution string."),
    ("ransomware_api", b"cryptencrypt", "medium", 20,
     "Contains a Windows cryptographic API reference; context may be benign."),
]


def _hash_file(path: Path) -> tuple[str, str, int, bytes]:
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    sample = bytearray()
    size = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            sha.update(block)
            md5.update(block)
            if len(sample) < SAMPLE_LIMIT:
                sample.extend(block[:SAMPLE_LIMIT - len(sample)])
    return sha.hexdigest(), md5.hexdigest(), size, bytes(sample)


def _file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE/Windows executable"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O executable"
    stripped = data.lstrip()
    if stripped.startswith(b"#!"):
        return "script"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"%PDF"):
        return "PDF document"
    if not data:
        return "empty file"
    if b"\x00" not in data[:4096]:
        return "text or script"
    return "binary data"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def _pe_findings(data: bytes, full_size: int | None) -> list[Finding]:
    findings: list[Finding] = []
    if len(data) < 64:
        return [Finding("malformed_pe_header", "medium", 25,
                        "PE file is shorter than a valid DOS header.")]
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 64 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return [Finding("malformed_pe_header", "medium", 25,
                        "PE signature or COFF header is invalid or truncated.")]
    section_count = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
    if not 1 <= section_count <= 96:
        findings.append(Finding("unusual_pe_section_count", "low", 10,
                                f"PE declares an unusual {section_count}-section layout."))
        return findings
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 2:
        return findings + [Finding("truncated_pe_optional_header", "medium", 20,
                                   "PE optional header is truncated or inconsistent.")]
    magic = int.from_bytes(data[optional:optional + 2], "little")
    if magic not in (0x10B, 0x20B):
        return findings + [Finding("invalid_pe_optional_magic", "medium", 20,
                                   "PE optional header has an unsupported magic value.")]
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        return findings + [Finding("truncated_pe_section_table", "medium", 20,
                                   "PE section table is truncated in the inspected file data.")]
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        raw_size = int.from_bytes(data[offset + 16:offset + 20], "little")
        raw_offset = int.from_bytes(data[offset + 20:offset + 24], "little")
        flags = int.from_bytes(data[offset + 36:offset + 40], "little")
        if flags & 0x20000000 and flags & 0x80000000:
            findings.append(Finding("pe_writable_executable_section", "medium", 20,
                                    f"PE section {name or index} is both writable and executable."))
        if name.upper().startswith("UPX"):
            findings.append(Finding("pe_upx_section_name", "low", 8,
                                    f"PE section {name} uses a common packer name."))
        actual_size = full_size if full_size is not None else len(data)
        if raw_size and raw_offset + raw_size > actual_size:
            findings.append(Finding("pe_section_out_of_bounds", "medium", 20,
                                    f"PE section {name or index} extends beyond the file."))
        if raw_size >= 1024 and raw_offset < len(data):
            section = data[raw_offset:min(raw_offset + raw_size, len(data))]
            if len(section) >= 1024 and _entropy(section) >= 7.35:
                findings.append(Finding("high_entropy_pe_section", "low", 10,
                                        f"PE section {name or index} has high entropy; packing is one possible cause."))
    return findings


def _static_findings(data: bytes, file_type: str, full_size: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    lowered = data.lower()
    if file_type == "PE/Windows executable":
        findings.extend(_pe_findings(data, full_size))
    if file_type == "ELF executable":
        header_size = 64 if len(data) > 4 and data[4] == 2 else 52
        if len(data) < header_size or data[4] not in (1, 2) or data[5] not in (1, 2):
            findings.append(Finding("malformed_elf_header", "medium", 25,
                                    "ELF class, byte order, or header size is invalid."))
    if file_type == "Mach-O executable":
        header_size = 32 if data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 28
        if len(data) < header_size:
            findings.append(Finding("truncated_macho_header", "medium", 25,
                                    "Mach-O header is truncated."))
    for rule, needle, severity, points, description in PATTERNS:
        if needle.lower() in lowered:
            evidence = needle.decode("ascii", errors="replace")
            findings.append(Finding(rule, severity, points, description, evidence))
    if len(data) >= 4096 and not any(data.startswith(magic) for magic in
                                     (b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF")):
        portion = data[:65536]
        nontext = sum(1 for b in portion if b == 0 or (b < 9) or (13 < b < 32)) / len(portion)
        if nontext > 0.35:
            findings.append(Finding("high_binary_entropy_proxy", "low", 8,
                                    "Unrecognized data contains many non-text bytes; this is weak evidence."))
    return findings


@functools.lru_cache(maxsize=1)
def _compiled_yara_rules():
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        return yara.compile(filepath=str(YARA_RULES))
    except Exception:
        return None


def yara_available() -> bool:
    return importlib.util.find_spec("yara") is not None and _compiled_yara_rules() is not None


def _yara_findings(data: bytes) -> list[Finding]:
    rules = _compiled_yara_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(data=data, timeout=2)
    except Exception:
        return []
    return [Finding(match.rule, "medium", 20, "Matched bundled YARA rule.") for match in matches]


def scan_file(path: Path | str, db=None, *, archive: bool = True, clamav=None) -> ScanResult:
    target = Path(path)
    result = ScanResult(path=str(target))
    try:
        target = assert_no_link_components(target)
        st = target.lstat()
        if is_linklike(target, st) or not stat.S_ISREG(st.st_mode):
            raise ValueError("Refusing symlinks and non-regular files")
        result.sha256, result.md5, result.size, sample = _hash_file(target)
        result.file_type = _file_type(sample)
        if db:
            for name, severity, source in db.lookup(result.sha256, result.md5):
                points = {"low": 15, "medium": 35, "high": 70, "critical": 90}.get(severity, 70)
                result.findings.append(Finding("known_hash", severity, points,
                                               f"Hash matched local signature: {name}", source))
        result.findings.extend(_static_findings(sample, result.file_type, result.size))
        result.findings.extend(_yara_findings(sample))
        if yara_available():
            result.engines.append("YARA")
        else:
            result.warnings.append("Optional YARA engine is unavailable; built-in static checks still ran.")
        if clamav:
            if hasattr(clamav, "scan_many"):
                findings, warnings, names = clamav.scan_many(target)
                result.engines.extend(names)
                result.findings.extend(findings)
                result.warnings.extend(warnings)
            else:
                result.engines.append("ClamAV")
                finding, warning = clamav.scan(target)
                if finding:
                    result.findings.append(finding)
                if warning:
                    result.warnings.append(warning)
        if archive and result.file_type == "ZIP archive":
            result.findings.extend(_scan_zip(target))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        result.errors.append(str(exc))
        result.status = "error"
    total = sum(f.points for f in result.findings)
    result.risk_score = min(100, total)
    result.risk_level = "critical" if total >= 80 else "high" if total >= 50 else "medium" if total >= 20 else "low"
    if result.status != "error" and result.risk_score >= 50:
        result.status = "threat"
    elif result.status != "error" and result.findings:
        result.status = "suspicious"
    return result


def _scan_zip(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if path.stat().st_size > ARCHIVE_SIZE_LIMIT:
        return [Finding("archive_size_limit", "low", 0,
                        f"Archive exceeds {ARCHIVE_SIZE_LIMIT // (1024 * 1024)} MiB inspection limit.")]
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > ARCHIVE_MEMBER_LIMIT:
            return [Finding("archive_member_limit", "low", 0,
                            f"Archive exceeds {ARCHIVE_MEMBER_LIMIT} member inspection limit.")]
        for info in entries:
            # Never extract. Ignore links and special files; cap declared and actual decompressed sizes.
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode) or info.is_dir():
                continue
            if info.file_size > ARCHIVE_MEMBER_SIZE_LIMIT:
                findings.append(Finding("archive_member_size_limit", "low", 0,
                                        f"Skipped oversized archive member: {Path(info.filename).name}"))
                continue
            try:
                with archive.open(info) as member:
                    data = member.read(ARCHIVE_MEMBER_SIZE_LIMIT + 1)
                if len(data) > ARCHIVE_MEMBER_SIZE_LIMIT:
                    continue
                typ = _file_type(data)
                for finding in _static_findings(data[:SAMPLE_LIMIT], typ):
                    finding.evidence = f"{Path(info.filename).name}: {finding.evidence}".strip(": ")
                    findings.append(finding)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                findings.append(Finding("archive_member_read_error", "low", 0,
                                        f"Could not inspect archive member: {Path(info.filename).name}"))
    return findings


def walk_files(paths: list[Path | str], *, max_files: int = FILE_COUNT_LIMIT):
    """Yield regular files without following symlinks; return errors as (None, message)."""
    seen_dirs: set[tuple[int, int]] = set()
    count = 0
    directory_count = 0
    def children(directory: Path):
        with os.scandir(directory) as entries:
            for entry in entries:
                yield Path(entry.path)

    stack = [(iter(reversed([Path(p) for p in paths])), None)]
    try:
        while stack:
            iterator, directory = stack[-1]
            try:
                path = next(iterator)
            except StopIteration:
                close = getattr(iterator, "close", None)
                if close:
                    close()
                stack.pop()
                continue
            except OSError as exc:
                close = getattr(iterator, "close", None)
                if close:
                    close()
                stack.pop()
                yield None, f"{directory}: {exc}"
                continue
            try:
                path = assert_no_link_components(path)
                st = path.lstat()
                if is_linklike(path, st):
                    continue
                if stat.S_ISREG(st.st_mode):
                    count += 1
                    if count > max_files:
                        yield None, f"Stopped at the {max_files} file safety limit"
                        return
                    yield path, None
                elif stat.S_ISDIR(st.st_mode):
                    ident = (st.st_dev, st.st_ino)
                    if ident in seen_dirs:
                        continue
                    directory_count += 1
                    if directory_count > DIRECTORY_COUNT_LIMIT:
                        yield None, f"Stopped at the {DIRECTORY_COUNT_LIMIT} directory safety limit"
                        return
                    seen_dirs.add(ident)
                    # Keep a lazy directory iterator instead of materializing or sorting
                    # every child, which can allocate heavily on large system folders.
                    stack.append((children(path), path))
            except OSError as exc:
                yield None, f"{path}: {exc}"
            except ValueError:
                # A symbolic link or reparse point in any path component is deliberately skipped.
                continue
    finally:
        for iterator, _directory in stack:
            close = getattr(iterator, "close", None)
            if close:
                close()
