"""Tests for the asynchronous AsyncThreatFeedClient."""

import json
from pathlib import Path

import pytest

from threat_feed_client import AsyncThreatFeedClient, PaginatedResponse

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


@pytest.fixture
def async_client(httpx_mock):
    return AsyncThreatFeedClient(api_token="test-token", base_url="https://test.0din.ai/api/v1")


class TestAsyncThreatFeedEndpoints:
    async def test_list_threat_feeds(self, async_client, httpx_mock):
        fixture = load_fixture("threat_feeds_list.json")
        httpx_mock.add_response(json=fixture)

        result = await async_client.list_threat_feeds()
        assert isinstance(result, PaginatedResponse)
        assert len(result.items) == 2

    async def test_get_threat_feed(self, async_client, httpx_mock):
        fixture = load_fixture("threat_feed_show.json")
        httpx_mock.add_response(json=fixture)

        feed = await async_client.get_threat_feed("31f21827-8474-4eb9-8392-ec59956f78e7")
        assert feed.title == "Disclosed Vuln"

    async def test_iter_threat_feeds(self, async_client, httpx_mock):
        page1 = {
            "page": 1, "total_pages": 2, "total_count": 3,
            "threat_feeds": load_fixture("threat_feeds_list.json")["threat_feeds"],
        }
        page2 = {
            "page": 2, "total_pages": 2, "total_count": 3,
            "threat_feeds": [load_fixture("threat_feed_show.json")],
        }
        httpx_mock.add_response(json=page1)
        httpx_mock.add_response(json=page2)

        feeds = []
        async for feed in async_client.iter_threat_feeds(per_page=2):
            feeds.append(feed)
        assert len(feeds) == 3


class TestAsyncVulnerabilityEndpoints:
    async def test_list_vulnerabilities(self, async_client, httpx_mock):
        fixture = {
            "page": 1, "total_pages": 1, "total_count": 1,
            "vulnerabilities": [load_fixture("vulnerability_show.json")],
        }
        httpx_mock.add_response(json=fixture)

        result = await async_client.list_vulnerabilities()
        assert len(result.items) == 1

    async def test_match_prompt(self, async_client, httpx_mock):
        fixture = load_fixture("match_result.json")
        httpx_mock.add_response(json=fixture)

        result = await async_client.match_prompt("test prompt")
        assert result.duplicate_probability == 0.85


class TestAsyncContextManager:
    async def test_async_context_manager(self, httpx_mock):
        httpx_mock.add_response(json=load_fixture("threat_feeds_list.json"))

        async with AsyncThreatFeedClient(api_token="test", base_url="https://test.0din.ai/api/v1") as client:
            result = await client.list_threat_feeds()
            assert len(result.items) == 2
