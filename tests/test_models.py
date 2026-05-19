"""Tests for Pydantic model deserialization using swagger fixture data."""

from tests.conftest import load_fixture

from threat_feed_client.models.attack import Attack
from threat_feed_client.models.comment import Comment
from threat_feed_client.models.match import MatchResult
from threat_feed_client.models.model import AIModel
from threat_feed_client.models.threat_feed import ThreatFeed
from threat_feed_client.models.vulnerability import Vulnerability


class TestThreatFeedModel:
    def test_parse_threat_feed_list(self):
        data = load_fixture("threat_feeds_list.json")
        feeds = [ThreatFeed.model_validate(item) for item in data["threat_feeds"]]
        assert len(feeds) == 2

        feed = feeds[0]
        assert feed.uuid == "31f21827-8474-4eb9-8392-ec59956f78e7"
        assert feed.title == "Disclosed Vuln"
        assert feed.severity.value == "low"
        assert feed.security_boundary.value == "guardrail_jailbreak"
        assert len(feed.models) == 1
        assert feed.models[0].name == "M6"
        assert feed.models[0].vendor.name == "Alibaba"
        assert len(feed.messages) == 1
        assert feed.messages[0].interface.value == "api"
        assert len(feed.taxonomies) == 1
        assert feed.taxonomies[0].category == "rhetoric"
        assert len(feed.test_results) == 1
        assert feed.test_results[0].test_type.name == "cve"
        assert len(feed.detection_signatures) == 1
        assert len(feed.metadata) == 1
        assert len(feed.reference_urls) == 1

    def test_parse_threat_feed_show(self):
        data = load_fixture("threat_feed_show.json")
        feed = ThreatFeed.model_validate(data)
        assert feed.uuid == "31f21827-8474-4eb9-8392-ec59956f78e7"
        assert len(feed.taxonomies) == 2
        assert len(feed.test_results) == 2
        assert len(feed.metadata) == 2

    def test_parse_threat_feed_with_multiple_models(self):
        data = load_fixture("threat_feeds_list.json")
        feed = ThreatFeed.model_validate(data["threat_feeds"][1])
        assert len(feed.models) == 2
        assert feed.models[1].name == "Hunyuan"
        assert feed.models[1].vendor.name == "Tencent"
        assert feed.published_at is not None


class TestVulnerabilityModel:
    def test_parse_vulnerability(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        assert vuln.uuid == "abc12345-1234-5678-9abc-def012345678"
        assert vuln.aasm_state.value == "offered"
        assert vuln.severity.value == "high"
        assert vuln.security_boundary.value == "prompt_extraction"
        assert vuln.bounty_amount == 500.0
        assert vuln.assignee_id == 42
        assert vuln.submitter_id == 7
        assert not vuln.awarded

    def test_vulnerability_vendor_is_flat_string(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        assert vuln.models[0].vendor == "OpenAI"

    def test_vulnerability_messages_have_ids(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        msg = vuln.messages[0]
        assert msg.id == 101
        assert msg.pinned is True
        assert msg.created_at is not None

    def test_vulnerability_feed_activities(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        assert len(vuln.feed) == 1
        assert vuln.feed[0].key == "vulnerability.create"

    def test_vulnerability_variant_prompts(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        assert len(vuln.variant_prompts) == 1
        assert vuln.variant_prompts[0].variant_prompt == "System prompt please"

    def test_vulnerability_taxonomies_have_ids(self):
        data = load_fixture("vulnerability_show.json")
        vuln = Vulnerability.model_validate(data)
        assert vuln.taxonomies[0].id == 5


class TestMatchResultModel:
    def test_parse_match_result(self):
        data = load_fixture("match_result.json")
        result = MatchResult.model_validate(data)
        assert result.duplicate_probability == 0.85
        assert result.signature_version == "3"
        assert len(result.matches) == 2
        assert result.matches[0].similarity == 0.85
        assert result.matches[1].title == "Similar Attack"


class TestAIModelModel:
    def test_parse_models_list(self):
        data = load_fixture("models_list.json")
        models = [AIModel.model_validate(item) for item in data["models"]]
        assert len(models) == 3
        assert models[0].name == "Gemini"
        assert models[0].vendor.name == "Google"
        assert not models[0].retired
        assert models[2].retired


class TestAttackModel:
    def test_parse_attack(self):
        data = load_fixture("attacks_list.json")
        attacks = [Attack.model_validate(item) for item in data["attacks"]]
        assert len(attacks) == 1
        attack = attacks[0]
        assert attack.vulnerability.uuid == "abc12345"
        assert len(attack.techniques) == 2
        assert len(attack.messages) == 1
        assert len(attack.text_anchors) == 1
        assert attack.text_anchors[0].anchor == "important text"


class TestCommentModel:
    def test_parse_comment(self):
        data = load_fixture("comment_created.json")
        comment = Comment.model_validate(data)
        assert comment.id == 1046006362
        assert comment.internal is True
        assert comment.comment == "This is a test comment"
