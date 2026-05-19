from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from .exceptions import (
    AuthenticationError,
    NotFoundError,
    OdinAPIError,
    RateLimitError,
    ServiceUnavailableError,
    ValidationError,
)

DEFAULT_BASE_URL = "https://0din.ai/api/v1"

# Load .env from the current working directory (if present). Does not override
# variables that are already set in the environment.
load_dotenv(Path.cwd() / ".env")


def resolve_api_token(api_token: str | None) -> str:
    token = api_token or os.environ.get("ODIN_API_TOKEN")
    if not token:
        raise AuthenticationError(
            "API token must be provided via the api_token parameter or the ODIN_API_TOKEN environment variable."
        )
    return token


def resolve_base_url(base_url: str | None) -> str:
    url = base_url or os.environ.get("ODIN_BASE_URL") or os.environ.get("ODIN_API_URL") or DEFAULT_BASE_URL
    url = url.rstrip("/")
    # If the URL doesn't already include the /api/v1 path, append it
    if not url.endswith("/api/v1"):
        url = url.rstrip("/") + "/api/v1"
    return url


def build_auth_headers(api_token: str) -> dict[str, str]:
    return {
        "Authorization": api_token,
        "Accept": "application/json",
    }


def raise_for_status(response: httpx.Response) -> None:
    """Map HTTP error responses to typed exceptions."""
    if response.is_success:
        return

    status = response.status_code
    try:
        body = response.text
    except Exception:
        body = None

    if status == 404:
        raise NotFoundError(
            "Not found (HTTP 404). Note: the 0DIN API also returns 404 for authentication failures.",
            status_code=status,
            response_body=body,
        )
    elif status == 422:
        errors = []
        try:
            data = response.json()
            if isinstance(data, dict):
                errors = data.get("errors", [])
            elif isinstance(data, list):
                errors = data
        except Exception:
            pass
        raise ValidationError(
            f"Validation error (HTTP 422): {errors}",
            status_code=status,
            response_body=body,
            errors=errors,
        )
    elif status == 429:
        raise RateLimitError(
            "Rate limit exceeded (HTTP 429).",
            status_code=status,
            response_body=body,
        )
    elif status == 503:
        raise ServiceUnavailableError(
            "Service unavailable (HTTP 503).",
            status_code=status,
            response_body=body,
        )
    else:
        raise OdinAPIError(
            f"API error (HTTP {status})",
            status_code=status,
            response_body=body,
        )


# Filters that require mapping string enum values to integer codes for the API.
SEVERITY_VALUES: dict[str, int] = {"low": 5, "medium": 10, "high": 15, "severe": 20}
SECURITY_BOUNDARY_VALUES: dict[str, int] = {
    "guardrail_jailbreak": 0,
    "prompt_extraction": 1,
    "interpreter_jailbreak": 2,
    "unbounded_consumption": 3,
    "content_manipulation": 4,
    "weights_and_layers_disclosure": 5,
    "other": 6,
    "prompt_injection": 7,
}
ENUM_INT_PARAMS: dict[str, dict[str, int]] = {
    "severity": SEVERITY_VALUES,
    "security_boundary": SECURITY_BOUNDARY_VALUES,
}

# Ransack query parameter mapping.
# Maps pythonic keyword arguments to the Ransack query parameter names used by the API.
RANSACK_PARAM_MAP: dict[str, str] = {
    "uuid_start": "q[uuid_start]",
    "title_contains": "q[title_cont]",
    "model_ids": "q[models_id_in][]",
    "states": "q[aasm_state_in][]",
    "security_boundary": "q[security_boundary_eq]",
    "severity": "q[severity_eq]",
    "test_type": "q[test_results_test_type_eq]",
    "test_result_min": "q[test_results_result_gteq]",
    "scanner_module_present": "q[scanner_module_id_not_null]",
    "taxonomy_category_id": "q[taxonomy_triplets_category_id_eq]",
    "taxonomy_strategy_id": "q[taxonomy_triplets_strategy_id_eq]",
    "taxonomy_technique_id": "q[taxonomy_triplets_technique_id_eq]",
    # Vulnerability-specific filters
    "keyword": "q[search_by_keyword]",
    "assignee_id": "q[assignee_id_eq]",
    "submitter_id": "q[submitter_id_eq]",
    "search_group": "q[search_group]",
    # Model-specific filters
    "model_id": "q[id_eq]",
    "name_contains": "q[name_cont]",
    "vendor_name_contains": "q[vendor_name_cont]",
    "retired": "q[retired_true]",
}


def build_query_params(
    *,
    page: int | None = None,
    per_page: int | None = None,
    **filters: Any,
) -> dict[str, Any]:
    """Build query parameters from pythonic kwargs, mapping to Ransack syntax."""
    params: dict[str, Any] = {}

    if page is not None:
        params["page"] = page
    if per_page is not None:
        params["per_page"] = min(per_page, 100)

    for key, value in filters.items():
        if value is None:
            continue
        ransack_key = RANSACK_PARAM_MAP.get(key)
        if ransack_key is None:
            raise ValueError(f"Unknown filter parameter: {key!r}")
        # Handle enum values (e.g. Severity.HIGH -> "high")
        if hasattr(value, "value"):
            value = value.value
        # Map string enum names to integer codes where the API requires it
        if key in ENUM_INT_PARAMS and isinstance(value, str):
            value = ENUM_INT_PARAMS[key].get(value, value)
        params[ransack_key] = value

    return params
