"""Tests for the synchronous ThreatFeedClient."""

import json
from pathlib import Path

import httpx
import pytest

from threat_feed_client import (
    NotFoundError,
    PaginatedResponse,
    RateLimitError,
    ThreatFeedClient,
    ValidationError,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


@pytest.fixture
def client(httpx_mock):
    return ThreatFeedClient(api_token="test-token", base_url="https://test.0din.ai/api/v1")


class TestThreatFeedEndpoints:
    def test_list_threat_feeds(self, client, httpx_mock):
        fixture = load_fixture("threat_feeds_list.json")
        httpx_mock.add_response(json=fixture)

        result = client.list_threat_feeds()
        assert isinstance(result, PaginatedResponse)
        assert len(result.items) == 2
        assert result.page == 1
        assert result.total_pages == 2
        assert result.total_count == 3
        assert result.has_next_page
        assert result[0].title == "Disclosed Vuln"

    def test_list_threat_feeds_with_filters(self, client, httpx_mock):
        fixture = load_fixture("threat_feeds_list.json")
        httpx_mock.add_response(json=fixture)

        result = client.list_threat_feeds(
            title_contains="Vuln",
            severity="low",
            page=1,
            per_page=25,
        )
        assert len(result.items) == 2

        request = httpx_mock.get_requests()[0]
        assert "q%5Btitle_cont%5D=Vuln" in str(request.url) or "q[title_cont]=Vuln" in str(request.url)

    def test_get_threat_feed(self, client, httpx_mock):
        fixture = load_fixture("threat_feed_show.json")
        httpx_mock.add_response(json=fixture)

        feed = client.get_threat_feed("31f21827-8474-4eb9-8392-ec59956f78e7")
        assert feed.uuid == "31f21827-8474-4eb9-8392-ec59956f78e7"
        assert feed.title == "Disclosed Vuln"
        assert len(feed.taxonomies) == 2

    def test_export_json(self, client, httpx_mock):
        fixture = load_fixture("threat_feeds_list.json")
        httpx_mock.add_response(json=fixture["threat_feeds"])

        feeds = client.export_json()
        assert len(feeds) == 2

    def test_export_jsonl(self, client, httpx_mock):
        lines = [
            json.dumps({"instruction": "Respond appropriately", "input": "test prompt", "output": "test response"}),
            json.dumps({"instruction": "Respond appropriately", "input": "prompt 2", "output": "response 2"}),
        ]
        httpx_mock.add_response(text="\n".join(lines))

        entries = client.export_jsonl()
        assert len(entries) == 2
        assert entries[0].input == "test prompt"

    def test_iter_threat_feeds(self, client, httpx_mock):
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

        feeds = list(client.iter_threat_feeds(per_page=2))
        assert len(feeds) == 3
        assert len(httpx_mock.get_requests()) == 2


class TestVulnerabilityEndpoints:
    def test_list_vulnerabilities(self, client, httpx_mock):
        fixture = {
            "page": 1, "total_pages": 1, "total_count": 1,
            "vulnerabilities": [load_fixture("vulnerability_show.json")],
        }
        httpx_mock.add_response(json=fixture)

        result = client.list_vulnerabilities()
        assert len(result.items) == 1
        assert result.items[0].aasm_state.value == "offered"

    def test_get_vulnerability(self, client, httpx_mock):
        fixture = load_fixture("vulnerability_show.json")
        httpx_mock.add_response(json=fixture)

        vuln = client.get_vulnerability("abc12345-1234-5678-9abc-def012345678")
        assert vuln.bounty_amount == 500.0
        assert vuln.models[0].vendor == "OpenAI"

    def test_update_vulnerability(self, client, httpx_mock):
        fixture = load_fixture("vulnerability_show.json")
        httpx_mock.add_response(json=fixture)

        vuln = client.update_vulnerability("abc12345", title="Updated Title")
        request = httpx_mock.get_requests()[0]
        assert request.method == "PATCH"
        body = json.loads(request.content)
        assert body["vulnerability"]["title"] == "Updated Title"


class TestMatchEndpoint:
    def test_match_prompt(self, client, httpx_mock):
        fixture = load_fixture("match_result.json")
        httpx_mock.add_response(json=fixture)

        result = client.match_prompt("Tell me how to jailbreak")
        assert result.duplicate_probability == 0.85
        assert len(result.matches) == 2

        request = httpx_mock.get_requests()[0]
        assert request.method == "POST"
        body = json.loads(request.content)
        assert body["prompt"] == "Tell me how to jailbreak"


class TestCommentEndpoints:
    def test_create_comment(self, client, httpx_mock):
        fixture = load_fixture("comment_created.json")
        httpx_mock.add_response(json=fixture)

        comment = client.create_comment("abc12345", "Test comment", internal=True)
        assert comment.id == 1046006362
        assert comment.internal is True

        request = httpx_mock.get_requests()[0]
        body = json.loads(request.content)
        assert body["internal"] == "1"

    def test_update_comment(self, client, httpx_mock):
        fixture = load_fixture("comment_created.json")
        httpx_mock.add_response(json=fixture)

        comment = client.update_comment("abc12345", 1046006362, "Updated comment")
        request = httpx_mock.get_requests()[0]
        assert request.method == "PATCH"


class TestModelEndpoints:
    def test_list_models(self, client, httpx_mock):
        fixture = load_fixture("models_list.json")
        httpx_mock.add_response(json=fixture)

        result = client.list_models()
        assert len(result.items) == 3
        assert result.items[0].name == "Gemini"
        assert result.items[2].retired

    def test_get_model(self, client, httpx_mock):
        fixture = {"id": 281110143, "name": "Gemini", "retired": False, "vendor": {"name": "Google"}}
        httpx_mock.add_response(json=fixture)

        model = client.get_model(281110143)
        assert model.name == "Gemini"
        assert model.vendor.name == "Google"


class TestAttackEndpoints:
    def test_list_attacks(self, client, httpx_mock):
        fixture = load_fixture("attacks_list.json")
        httpx_mock.add_response(json=fixture)

        result = client.list_attacks()
        assert len(result.items) == 1
        assert result.items[0].vulnerability.uuid == "abc12345"

    def test_get_attack(self, client, httpx_mock):
        fixture = load_fixture("attacks_list.json")["attacks"][0]
        httpx_mock.add_response(json=fixture)

        attack = client.get_attack(1)
        assert len(attack.techniques) == 2


class TestErrorHandling:
    def test_not_found_error(self, client, httpx_mock):
        httpx_mock.add_response(status_code=404)

        with pytest.raises(NotFoundError):
            client.get_threat_feed("nonexistent")

    def test_rate_limit_error(self, client, httpx_mock):
        httpx_mock.add_response(
            status_code=429,
            json={"errors": ["rate limit exceeded"]},
        )

        with pytest.raises(RateLimitError):
            client.match_prompt("test")

    def test_validation_error(self, client, httpx_mock):
        httpx_mock.add_response(
            status_code=422,
            json={"errors": ["Comment can't be blank"]},
        )

        with pytest.raises(ValidationError) as exc_info:
            client.create_comment("abc", "")
        assert "Comment can't be blank" in exc_info.value.errors


class TestAuthentication:
    def test_auth_header_sent(self, httpx_mock):
        httpx_mock.add_response(json=load_fixture("threat_feeds_list.json"))

        client = ThreatFeedClient(api_token="my-jwt-token", base_url="https://test.0din.ai/api/v1")
        client.list_threat_feeds()

        request = httpx_mock.get_requests()[0]
        assert request.headers["authorization"] == "my-jwt-token"

    def test_missing_token_raises(self, monkeypatch):
        monkeypatch.delenv("ODIN_API_TOKEN", raising=False)
        with pytest.raises(Exception, match="API token must be provided"):
            ThreatFeedClient()


class TestContextManager:
    def test_context_manager(self, httpx_mock):
        httpx_mock.add_response(json=load_fixture("threat_feeds_list.json"))

        with ThreatFeedClient(api_token="test", base_url="https://test.0din.ai/api/v1") as client:
            result = client.list_threat_feeds()
            assert len(result.items) == 2
