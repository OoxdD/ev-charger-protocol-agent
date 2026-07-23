from __future__ import annotations

from typing import Any

from evcpa.models import ProtocolId
from evcpa.protocols import ProtocolParser, all_parsers


def rank_protocols(
    raw: bytes | None,
    json_obj: Any | None,
    parsers: list[ProtocolParser] | None = None,
) -> list[tuple[ProtocolParser, float]]:
    parsers = parsers or all_parsers()
    ranked = [(p, p.detect_score(raw, json_obj)) for p in parsers]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def detect_best(
    raw: bytes | None,
    json_obj: Any | None,
    preferred: ProtocolId | None = None,
    parsers: list[ProtocolParser] | None = None,
) -> tuple[ProtocolParser | None, float, list[tuple[str, float]]]:
    ranked = rank_protocols(raw, json_obj, parsers)
    candidates = [(p.protocol_id.value, score) for p, score in ranked]

    if preferred and preferred != ProtocolId.UNKNOWN:
        for p, score in ranked:
            if p.protocol_id == preferred:
                return p, max(score, 0.99), candidates

    if not ranked or ranked[0][1] <= 0:
        return None, 0.0, candidates
    return ranked[0][0], ranked[0][1], candidates
