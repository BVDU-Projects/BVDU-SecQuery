"""Passphrase-protected AES-256-GCM quarantine vault."""
import hashlib
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .safety import assert_no_link_components, is_linklike

MAGIC = b"BVDQ1\x00"
MAX_FILE_SIZE = 256 * 1024 * 1024
SALT_BYTES = 16
NONCE_BYTES = 12


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Passphrase must be at least 12 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def _restrict(path: Path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows permissions are inherited from the containing directory.


def quarantine_file(source: Path | str, vault: Path | str, passphrase: str,
                    expected_sha256: str | None = None) -> Path:
    src, root = assert_no_link_components(source), assert_no_link_components(vault)
    st = src.lstat()
    if is_linklike(src, st) or not stat.S_ISREG(st.st_mode):
        raise ValueError("Refusing symlinks and non-regular files")
    if st.st_size > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MiB quarantine limit")
    root.mkdir(parents=True, exist_ok=True)
    if is_linklike(root):
        raise ValueError("Vault directory cannot be a symlink")
    os.chmod(root, 0o700)
    fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("File changed while opening; refusing quarantine")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            plaintext = handle.read(MAX_FILE_SIZE + 1)
        if len(plaintext) > MAX_FILE_SIZE:
            raise ValueError("File exceeded quarantine size limit while being read")
    finally:
        os.close(fd)
    salt, nonce = secrets.token_bytes(SALT_BYTES), secrets.token_bytes(NONCE_BYTES)
    digest = hashlib.sha256(plaintext).digest()
    if expected_sha256 and not secrets.compare_digest(digest.hex(), expected_sha256.lower()):
        raise ValueError("File contents changed after scanning; refusing quarantine")
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, digest + plaintext, MAGIC + salt)
    destination = root / (secrets.token_hex(16) + ".bvdq")
    payload = MAGIC + salt + nonce + ciphertext
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    _restrict(destination)
    # Validate the durable vault entry before removing the original path.
    verified = AESGCM(_derive(passphrase, salt)).decrypt(nonce, destination.read_bytes()[header_length():], MAGIC + salt)
    if len(verified) < 32 or not secrets.compare_digest(verified[:32], hashlib.sha256(verified[32:]).digest()):
        destination.unlink(missing_ok=True)
        raise ValueError("Vault verification failed; original file was retained")
    current = src.lstat()
    if ((current.st_dev, current.st_ino) != (st.st_dev, st.st_ino)
            or current.st_size != st.st_size or current.st_mtime_ns != st.st_mtime_ns):
        raise ValueError(f"File changed during quarantine; encrypted copy retained at {destination}")
    src.unlink()
    return destination


def header_length() -> int:
    return len(MAGIC) + SALT_BYTES + NONCE_BYTES


def restore_file(entry: Path | str, destination: Path | str, passphrase: str) -> str:
    source, output = assert_no_link_components(entry), assert_no_link_components(destination)
    if is_linklike(source) or not source.is_file():
        raise ValueError("Quarantine entry must be a regular file")
    if source.stat().st_size > MAX_FILE_SIZE + header_length() + 32 + 16:
        raise ValueError("Quarantine entry exceeds the supported size limit")
    raw = source.read_bytes()
    header = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if len(raw) < header + 16 or not raw.startswith(MAGIC):
        raise ValueError("Invalid quarantine file")
    offset = len(MAGIC)
    salt, nonce = raw[offset:offset + SALT_BYTES], raw[offset + SALT_BYTES:header]
    plaintext = AESGCM(_derive(passphrase, salt)).decrypt(nonce, raw[header:], MAGIC + salt)
    if len(plaintext) < 32:
        raise ValueError("Decrypted payload is truncated")
    expected, data = plaintext[:32], plaintext[32:]
    actual = hashlib.sha256(data).digest()
    if not secrets.compare_digest(expected, actual):
        raise ValueError("Integrity verification failed")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        output.unlink(missing_ok=True)
        raise
    _restrict(output)
    return actual.hex()
