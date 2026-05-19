from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Iterator, TypeVar

T = TypeVar("T")


@dataclass
class PaginatedResponse(Generic[T]):
    """A single page of results from a paginated API endpoint."""

    items: list[T]
    page: int
    total_pages: int
    total_count: int

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, index: int) -> T:
        return self.items[index]

    @property
    def has_next_page(self) -> bool:
        return self.page < self.total_pages
