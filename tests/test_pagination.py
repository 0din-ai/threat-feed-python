"""Tests for PaginatedResponse and query parameter building."""

from threat_feed_client._base import build_query_params
from threat_feed_client._pagination import PaginatedResponse


class TestPaginatedResponse:
    def test_iteration(self):
        resp = PaginatedResponse(items=["a", "b", "c"], page=1, total_pages=1, total_count=3)
        assert list(resp) == ["a", "b", "c"]

    def test_len(self):
        resp = PaginatedResponse(items=["a", "b"], page=1, total_pages=1, total_count=2)
        assert len(resp) == 2

    def test_getitem(self):
        resp = PaginatedResponse(items=["a", "b", "c"], page=1, total_pages=1, total_count=3)
        assert resp[0] == "a"
        assert resp[2] == "c"

    def test_has_next_page_true(self):
        resp = PaginatedResponse(items=[], page=1, total_pages=3, total_count=30)
        assert resp.has_next_page

    def test_has_next_page_false(self):
        resp = PaginatedResponse(items=[], page=3, total_pages=3, total_count=30)
        assert not resp.has_next_page


class TestBuildQueryParams:
    def test_empty_params(self):
        params = build_query_params()
        assert params == {}

    def test_page_and_per_page(self):
        params = build_query_params(page=2, per_page=50)
        assert params == {"page": 2, "per_page": 50}

    def test_per_page_capped_at_100(self):
        params = build_query_params(per_page=200)
        assert params["per_page"] == 100

    def test_ransack_filters(self):
        params = build_query_params(title_contains="jailbreak", severity="high")
        assert params["q[title_cont]"] == "jailbreak"
        assert params["q[severity_eq]"] == 15  # "high" maps to integer 15

    def test_none_values_skipped(self):
        params = build_query_params(title_contains=None, severity="low")
        assert "q[title_cont]" not in params
        assert params["q[severity_eq]"] == 5  # "low" maps to integer 5

    def test_list_values(self):
        params = build_query_params(states=["published", "disclosed"])
        assert params["q[aasm_state_in][]"] == ["published", "disclosed"]
