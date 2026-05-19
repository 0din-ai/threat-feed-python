from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AttackVulnerability(BaseModel):
    uuid: str
    summary: str | None = None


class AttackMessage(BaseModel):
    id: int
    prompt: str
    response: str
    model_id: int | None = None
    interface: str | None = None
    pinned: bool = False
    test_types: list[str] = []


class TextAnchor(BaseModel):
    id: int
    anchor: str
    replacements: Any = None
    transformation: str | None = None


class Attack(BaseModel):
    id: int
    vulnerability: AttackVulnerability
    techniques: list[str] = []
    created_at: datetime
    updated_at: datetime
    test_types: list[str] = []
    messages: list[AttackMessage] = []
    text_anchors: list[TextAnchor] = []
