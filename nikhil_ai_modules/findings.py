"""Standard finding model and duplicate grouping."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from nikhil_ai_modules.evidence import sanitize_value

STATUSES = {"NEW", "NEEDS_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "REPORTED", "RESOLVED"}
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
CONFIDENCES = {"LOW", "MEDIUM", "HIGH"}


@dataclass
class Finding:
    title: str
    category: str
    target: str
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    severity: str = "Info"
    confidence: str = "LOW"
    description: str = ""
    impact: str = ""
    evidence: Any = field(default_factory=list)
    observed_behavior: str = ""
    reproduction_notes: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    status: str = "NEEDS_REVIEW"
    finding_id: Optional[str] = None
    affected_endpoints: List[str] = field(default_factory=list)
    module: str = ""
    researcher_notes: str = ""

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        self.confidence = self.confidence.upper()
        self.status = self.status.upper()
        if self.severity not in SEVERITIES:
            self.severity = "INFO"
        if self.confidence not in CONFIDENCES:
            self.confidence = "LOW"
        if self.status not in STATUSES:
            self.status = "NEEDS_REVIEW"
        # Automated results can never enter the human-confirmed state.
        if not self.finding_id and self.status == "CONFIRMED":
            self.status = "NEEDS_REVIEW"
        if not self.finding_id:
            self.finding_id = "F-" + uuid.uuid4().hex[:10].upper()
        self.evidence = sanitize_value(self.evidence)
        self.references = [str(item)[:500] for item in (self.references or [])]
        self.affected_endpoints = list(dict.fromkeys(
            x for x in [self.endpoint, *(self.affected_endpoints or [])] if x
        ))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: Dict[str, Any]) -> "Finding":
        allowed = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in values.items() if key in allowed})


def _finding_host(target: str) -> str:
    try:
        return (urlsplit(target).hostname or target).lower().rstrip(".")
    except Exception:
        return target.lower().rstrip(".")


def fingerprint_finding(finding: Finding | Dict[str, Any]) -> str:
    item = finding.to_dict() if isinstance(finding, Finding) else finding
    canonical = {
        "category": str(item.get("category", "")).strip().lower(),
        "title": str(item.get("title", "")).strip().lower(),
        "target": _finding_host(str(item.get("target", ""))),
        "parameter": str(item.get("parameter") or "").strip().lower(),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()


class FindingManager:
    def __init__(self, database, project_id: int):
        self.database = database
        self.project_id = project_id

    def add(self, finding: Finding | Dict[str, Any]) -> Dict[str, Any]:
        model = finding if isinstance(finding, Finding) else Finding.from_dict(finding)
        payload = model.to_dict()
        # Do not trust a scanner-supplied status to mark automated output confirmed.
        if payload["status"] == "CONFIRMED":
            payload["status"] = "NEEDS_REVIEW"
        fingerprint = fingerprint_finding(payload)
        finding_id, created = self.database.add_finding(self.project_id, payload, fingerprint)
        payload["finding_id"] = finding_id
        payload["was_created"] = created
        return payload
