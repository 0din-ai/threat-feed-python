from __future__ import annotations

from pydantic import BaseModel

from .threat_feed import Vendor


class AIModel(BaseModel):
    id: int
    name: str
    retired: bool = False
    vendor: Vendor
