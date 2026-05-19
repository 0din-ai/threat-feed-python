from __future__ import annotations


class OdinAPIError(Exception):
    """Base exception for all 0DIN API errors."""

    def __init__(self, message: str, *, status_code: int | None = None, response_body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthenticationError(OdinAPIError):
    """Raised when the API token is missing, invalid, or lacks required permissions.

    Note: The 0DIN API returns HTTP 404 for authentication failures, making them
    indistinguishable from genuine not-found errors at the HTTP level.
    """


class NotFoundError(OdinAPIError):
    """Raised when the requested resource does not exist."""


class RateLimitError(OdinAPIError):
    """Raised when the API rate limit is exceeded (HTTP 429)."""


class ValidationError(OdinAPIError):
    """Raised when the API rejects the request due to validation errors (HTTP 422)."""

    def __init__(self, message: str, *, errors: list[str] | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.errors = errors or []


class ServiceUnavailableError(OdinAPIError):
    """Raised when an upstream service is unavailable (HTTP 503)."""
