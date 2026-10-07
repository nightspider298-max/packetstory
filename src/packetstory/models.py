"""Typed data models used by the PacketStory analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class TimelineEvent:
    timestamp: str
    kind: str
    summary: str
    source: str | None = None
    destination: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Indicator:
    value: str
    kind: str
    label: str = "Observed"
    reason: str = "Observed directly in packet metadata."
    first_seen: str | None = None


@dataclass(slots=True)
class Conversation:
    protocol: str
    source: str
    source_port: int | None
    destination: str
    destination_port: int | None
    packets: int = 0
    bytes: int = 0
    syn_attempts: int = 0


@dataclass(slots=True)
class CaptureAnalysis:
    capture: dict[str, Any]
    statistics: dict[str, Any]
    timeline: list[TimelineEvent] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    conversations: list[Conversation] = field(default_factory=list)
    dns: list[dict[str, Any]] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)
    tls: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible analysis data."""
        return asdict(self)


def iso_timestamp(epoch: float) -> str:
    """Format an epoch value in UTC with millisecond precision."""
    return (
        datetime.fromtimestamp(epoch, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
