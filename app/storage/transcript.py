"""Append-only transcript + TranscriptHash helpers.

This module provides a small, in-memory transcript that can later be
serialized, hashed, and signed as part of a SessionReceipt.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
import json
import hashlib


@dataclass
class TranscriptEvent:
    """
    One entry in the transcript.

    direction: "client" or "server" (or any short label)
    kind: short description of the event ("login_ok", "chat_msg", etc.)
    details: optional extra data (e.g., username, message length)
    ts: ISO 8601 timestamp in UTC
    """
    direction: str
    kind: str
    details: Dict[str, Any]
    ts: str


class Transcript:
    """Append-only transcript of important protocol events."""

    def __init__(self) -> None:
        self._events: List[TranscriptEvent] = []

    def add_event(self, direction: str, kind: str, details: Dict[str, Any] | None = None) -> None:
        """Append a new event to the transcript."""
        if details is None:
            details = {}

        evt = TranscriptEvent(
            direction=direction,
            kind=kind,
            details=details,
            ts=datetime.now(timezone.utc).isoformat(),
        )
        self._events.append(evt)

    @property
    def events(self) -> List[TranscriptEvent]:
        """Return a copy of the list of events (read-only)."""
        return list(self._events)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize transcript to a plain dict suitable for JSON."""
        return {
            "events": [asdict(e) for e in self._events],
        }

    def to_json(self) -> str:
        """Serialize transcript to canonical JSON (sorted keys, no extra spaces)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        """Compute SHA-256 hash (hex) of the transcript JSON."""
        data = self.to_json().encode("utf-8")
        return hashlib.sha256(data).hexdigest()


@dataclass
class TranscriptHash:
    """Lightweight wrapper for a transcript hash value."""
    algorithm: str
    value_hex: str


def make_transcript_hash(transcript: Transcript) -> TranscriptHash:
    """
    Produce a TranscriptHash from a Transcript instance.

    Example:
        t = Transcript()
        t.add_event("client", "login_ok", {"user": "bob"})
        th = make_transcript_hash(t)
    """
    return TranscriptHash(
        algorithm="SHA256",
        value_hex=transcript.compute_hash(),
    )
