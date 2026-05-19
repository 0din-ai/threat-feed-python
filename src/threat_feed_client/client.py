from __future__ import annotations

import time
from typing import Any, Iterator

import httpx
from pydantic import TypeAdapter
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from ._base import (
    build_auth_headers,
    build_query_params,
    raise_for_status,
    resolve_api_token,
    resolve_base_url,
)
from ._pagination import PaginatedResponse
from .exceptions import OdinAPIError
from .models.attack import Attack
from .models.comment import Comment
from .models.match import MatchResult
from .models.model import AIModel
from .models.threat_feed import InstructionTuningEntry, ThreatFeed
from .models.vulnerability import Vulnerability


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, OdinAPIError) and exc.status_code is not None and exc.status_code >= 500:
        return True
    return False


class ThreatFeedClient:
    """Synchronous client for the 0DIN Threat Feed API.

    Usage::

        with ThreatFeedClient(api_token="...") as client:
            feeds = client.list_threat_feeds()
            for feed in feeds:
                print(feed.title)

        # Or without context manager:
        client = ThreatFeedClient()  # reads ODIN_API_TOKEN env var
        feeds = client.list_threat_feeds()
        client.close()
    """

    def __init__(
        self,
        api_token: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        page_delay: float = 0.5,
    ):
        self._api_token = resolve_api_token(api_token)
        self._base_url = resolve_base_url(base_url)
        self._max_retries = max_retries
        self._page_delay = page_delay
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=build_auth_headers(self._api_token),
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ThreatFeedClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        @retry(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        )
        def _do() -> httpx.Response:
            response = self._client.request(method, path, **kwargs)
            raise_for_status(response)
            return response

        return _do()

    # ── Threat Feed endpoints ──────────────────────────────────────────

    def list_threat_feeds(
        self,
        *,
        page: int | None = None,
        per_page: int | None = None,
        uuid_start: str | None = None,
        title_contains: str | None = None,
        model_ids: list[int] | None = None,
        states: list[str] | None = None,
        security_boundary: int | str | None = None,
        severity: int | str | None = None,
        test_type: str | None = None,
        test_result_min: float | None = None,
        scanner_module_present: bool | None = None,
        taxonomy_category_id: int | None = None,
        taxonomy_strategy_id: int | None = None,
        taxonomy_technique_id: int | None = None,
    ) -> PaginatedResponse[ThreatFeed]:
        params = build_query_params(
            page=page,
            per_page=per_page,
            uuid_start=uuid_start,
            title_contains=title_contains,
            model_ids=model_ids,
            states=states,
            security_boundary=security_boundary,
            severity=severity,
            test_type=test_type,
            test_result_min=test_result_min,
            scanner_module_present=scanner_module_present,
            taxonomy_category_id=taxonomy_category_id,
            taxonomy_strategy_id=taxonomy_strategy_id,
            taxonomy_technique_id=taxonomy_technique_id,
        )
        response = self._request("GET", "/threatfeed", params=params)
        data = response.json()
        return PaginatedResponse(
            items=[ThreatFeed.model_validate(item) for item in data.get("threat_feeds", [])],
            page=data.get("page", 1),
            total_pages=data.get("total_pages", 1),
            total_count=data.get("total_count", 0),
        )

    def get_threat_feed(self, uuid: str) -> ThreatFeed:
        response = self._request("GET", f"/threatfeed/{uuid}")
        return ThreatFeed.model_validate(response.json())

    def export_json(self) -> list[ThreatFeed]:
        response = self._request("GET", "/threatfeed/export_json")
        adapter = TypeAdapter(list[ThreatFeed])
        return adapter.validate_python(response.json())

    def export_jsonl(self) -> list[InstructionTuningEntry]:
        response = self._request("GET", "/threatfeed/export_jsonl")
        lines = response.text.strip().split("\n")
        adapter = TypeAdapter(InstructionTuningEntry)
        return [adapter.validate_json(line) for line in lines if line.strip()]

    def iter_threat_feeds(self, *, per_page: int = 100, **filters: Any) -> Iterator[ThreatFeed]:
        """Auto-paginating iterator over all threat feeds matching the given filters."""
        page = 1
        while True:
            result = self.list_threat_feeds(page=page, per_page=per_page, **filters)
            yield from result.items
            if not result.has_next_page:
                break
            page += 1
            time.sleep(self._page_delay)

    # ── Vulnerability endpoints (admin) ────────────────────────────────

    def list_vulnerabilities(
        self,
        *,
        page: int | None = None,
        per_page: int | None = None,
        uuid_start: str | None = None,
        title_contains: str | None = None,
        keyword: str | None = None,
        states: list[str] | None = None,
        assignee_id: int | None = None,
        submitter_id: int | None = None,
        search_group: str | None = None,
        security_boundary: int | str | None = None,
        severity: int | str | None = None,
        model_ids: list[int] | None = None,
    ) -> PaginatedResponse[Vulnerability]:
        params = build_query_params(
            page=page,
            per_page=per_page,
            uuid_start=uuid_start,
            title_contains=title_contains,
            keyword=keyword,
            states=states,
            assignee_id=assignee_id,
            submitter_id=submitter_id,
            search_group=search_group,
            security_boundary=security_boundary,
            severity=severity,
            model_ids=model_ids,
        )
        response = self._request("GET", "/vulnerabilities", params=params)
        data = response.json()
        return PaginatedResponse(
            items=[Vulnerability.model_validate(item) for item in data.get("vulnerabilities", [])],
            page=data.get("page", 1),
            total_pages=data.get("total_pages", 1),
            total_count=data.get("total_count", 0),
        )

    def get_vulnerability(self, uuid: str) -> Vulnerability:
        response = self._request("GET", f"/vulnerabilities/{uuid}")
        return Vulnerability.model_validate(response.json())

    def update_vulnerability(self, uuid: str, **fields: Any) -> Vulnerability:
        response = self._request("PATCH", f"/vulnerabilities/{uuid}", json={"vulnerability": fields})
        return Vulnerability.model_validate(response.json())

    def iter_vulnerabilities(self, *, per_page: int = 100, **filters: Any) -> Iterator[Vulnerability]:
        """Auto-paginating iterator over all vulnerabilities matching the given filters."""
        page = 1
        while True:
            result = self.list_vulnerabilities(page=page, per_page=per_page, **filters)
            yield from result.items
            if not result.has_next_page:
                break
            page += 1
            time.sleep(self._page_delay)

    # ── Match endpoint (sdk_access) ────────────────────────────────────

    def match_prompt(self, prompt: str) -> MatchResult:
        response = self._request("POST", "/vulnerabilities/match", json={"prompt": prompt})
        return MatchResult.model_validate(response.json())

    # ── Comment endpoints (admin) ──────────────────────────────────────

    def create_comment(self, vulnerability_uuid: str, comment: str, *, internal: bool = False) -> Comment:
        response = self._request(
            "POST",
            f"/vulnerabilities/{vulnerability_uuid}/comments",
            json={"comment": comment, "internal": "1" if internal else "0"},
        )
        return Comment.model_validate(response.json())

    def update_comment(self, vulnerability_uuid: str, comment_id: int, comment: str) -> Comment:
        response = self._request(
            "PATCH",
            f"/vulnerabilities/{vulnerability_uuid}/comments/{comment_id}",
            json={"comment": comment},
        )
        return Comment.model_validate(response.json())

    # ── Model endpoints (researcher) ───────────────────────────────────

    def list_models(
        self,
        *,
        page: int | None = None,
        per_page: int | None = None,
        model_id: int | None = None,
        name_contains: str | None = None,
        vendor_name_contains: str | None = None,
    ) -> PaginatedResponse[AIModel]:
        params = build_query_params(
            page=page,
            per_page=per_page,
            model_id=model_id,
            name_contains=name_contains,
            vendor_name_contains=vendor_name_contains,
        )
        response = self._request("GET", "/researcher/models", params=params)
        data = response.json()
        return PaginatedResponse(
            items=[AIModel.model_validate(item) for item in data.get("models", [])],
            page=data.get("page", 1),
            total_pages=data.get("total_pages", 1),
            total_count=data.get("total_count", 0),
        )

    def get_model(self, model_id: int) -> AIModel:
        response = self._request("GET", f"/researcher/models/{model_id}")
        return AIModel.model_validate(response.json())

    def iter_models(self, *, per_page: int = 100, **filters: Any) -> Iterator[AIModel]:
        """Auto-paginating iterator over all models matching the given filters."""
        page = 1
        while True:
            result = self.list_models(page=page, per_page=per_page, **filters)
            yield from result.items
            if not result.has_next_page:
                break
            page += 1
            time.sleep(self._page_delay)

    # ── Attack endpoints (admin) ───────────────────────────────────────

    def list_attacks(
        self,
        *,
        page: int | None = None,
        per_page: int | None = None,
    ) -> PaginatedResponse[Attack]:
        params = build_query_params(page=page, per_page=per_page)
        response = self._request("GET", "/attacks", params=params)
        data = response.json()
        return PaginatedResponse(
            items=[Attack.model_validate(item) for item in data.get("attacks", [])],
            page=data.get("page", 1),
            total_pages=data.get("total_pages", 1),
            total_count=data.get("total_count", 0),
        )

    def get_attack(self, attack_id: int) -> Attack:
        response = self._request("GET", f"/attacks/{attack_id}")
        return Attack.model_validate(response.json())
