from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    rule: str
    severity: str
    points: int
    description: str
    evidence: str = ""


@dataclass
class ScanResult:
    path: str
    status: str = "clean"
    sha256: str = ""
    md5: str = ""
    size: int = 0
    file_type: str = "unknown"
    risk_score: int = 0
    risk_level: str = "low"
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    intel: list[dict[str, str]] = field(default_factory=list)
    engines: list[str] = field(default_factory=lambda: ["BVDU-SecQuery"])
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["findings"] = [asdict(item) for item in self.findings]
        return value
