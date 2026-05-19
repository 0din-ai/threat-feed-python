from __future__ import annotations

from pydantic import BaseModel


class MatchEntry(BaseModel):
    vulnerability_uuid: str
    title: str
    similarity: float


class MatchResult(BaseModel):
    duplicate_probability: float
    signature_version: str
    matches: list[MatchEntry] = []
