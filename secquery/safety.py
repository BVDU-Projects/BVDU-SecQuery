"""Filesystem checks shared by scanning and quarantine operations."""
import os
import stat
from pathlib import Path

WINDOWS_REPARSE_POINT = 0x400


def is_linklike(path: Path, info: os.stat_result | None = None) -> bool:
    info = info or path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT)


def assert_no_link_components(path: Path | str) -> Path:
    """Reject symlink/junction ancestors as well as a linked final component."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    cursor = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            # Later components cannot be inspected until this one exists.
            break
        if is_linklike(cursor, info):
            raise ValueError(f"Refusing path through a symlink or reparse point: {cursor}")
    return absolute
