from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class Comment(BaseModel):
    id: int
    created_at: datetime
    updated_at: datetime
    internal: bool = False
    comment: str
