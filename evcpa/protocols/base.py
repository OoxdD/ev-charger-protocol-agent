from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from evcpa.models import AnalysisResult, ProtocolId


class ProtocolParser(ABC):
    protocol_id: ProtocolId
    protocol_name: str

    @abstractmethod
    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        """Return confidence 0~1 that this payload belongs to the protocol."""

    @abstractmethod
    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        """Parse payload into a normalized analysis result."""
