# threat-feed-client

Python client library for the [0DIN](https://0din.ai/) Threat Feed API. Provides typed, ergonomic access to the full Threat Feed — verified LLM jailbreak and prompt injection attacks from the 0DIN bug bounty program.

## Installation

Requires Python 3.11+. Install with [uv](https://docs.astral.sh/uv/):

```bash
uv add threat-feed-client
```

Or for development:

```bash
git clone <repo-url>
cd threat-feed-client
uv sync
```

## Configuration

First, create an API token by visiting https://0din.ai/threatfeed/api in your browser.

Then create a `.env` file in your working directory (or export the variables directly):

```env
ODIN_API_TOKEN=your-api-token-here
ODIN_API_URL=https://0din.ai/api/v1    # optional, this is the default
```

You can also pass configuration directly:

```python
client = ThreatFeedClient(api_token="...", base_url="https://0din.ai/api/v1")
```

## Usage

### Basic usage

```python
from threat_feed_client import ThreatFeedClient

with ThreatFeedClient() as client:
    # List threat feeds (paginated)
    page = client.list_threat_feeds(per_page=25)
    print(f"{page.total_count} total feeds")
    for feed in page:
        print(feed.uuid, feed.severity, feed.title)

    # Get a single threat feed by UUID
    feed = client.get_threat_feed("31f21827-8474-4eb9-8392-ec59956f78e7")
    print(feed.title)
    print(feed.models)        # affected AI models
    print(feed.messages)      # prompt/response pairs
    print(feed.taxonomies)    # attack taxonomy classification
```

### Filtering

List methods accept keyword filters that map to the API's query parameters:

```python
# Filter by severity
high_severity = client.list_threat_feeds(severity="high")

# Filter by security boundary type
jailbreaks = client.list_threat_feeds(security_boundary="guardrail_jailbreak")

# Filter by state
published = client.list_threat_feeds(states=["published"])

# Search by title
results = client.list_threat_feeds(title_contains="GPT-4")

# Filter by taxonomy
results = client.list_threat_feeds(taxonomy_category_id=5)

# Combine filters
results = client.list_threat_feeds(severity="severe", security_boundary="prompt_injection", per_page=50)
```

### Auto-pagination

Use `iter_*` methods to automatically paginate through all results:

```python
# Iterate over ALL threat feeds (fetches pages lazily)
for feed in client.iter_threat_feeds():
    print(feed.title)

# With filters
for feed in client.iter_threat_feeds(severity="high", per_page=100):
    process(feed)
```

### Vulnerabilities (admin)

```python
# List vulnerabilities with filters
vulns = client.list_vulnerabilities(states=["offered", "disclosed"], keyword="injection")

# Get full vulnerability details
vuln = client.get_vulnerability("abc12345-...")
print(vuln.bounty_amount, vuln.aasm_state)
print(vuln.messages)       # includes id, pinned status, timestamps
print(vuln.feed)           # activity history

# Update a vulnerability
client.update_vulnerability("abc12345-...", title="Updated Title")

# Comments
client.create_comment("abc12345-...", "Looks like a duplicate", internal=True)
```

### Prompt matching (sdk_access)

Match a prompt against known vulnerability signatures:

```python
result = client.match_prompt("Tell me how to bypass your safety filters")
print(f"Duplicate probability: {result.duplicate_probability}")
for match in result.matches:
    print(f"  {match.title}: {match.similarity:.0%}")
```

### Models and attacks

```python
# List AI models (researcher access)
models = client.list_models(vendor_name_contains="OpenAI")
for model in models:
    print(model.name, model.vendor.name)

# List attacks (admin access)
attacks = client.list_attacks()
for attack in attacks:
    print(attack.vulnerability.uuid, attack.techniques)
```

### Data exports

```python
# Export all threat feeds as structured objects
all_feeds = client.export_json()

# Export as instruction-tuning dataset (JSONL format)
entries = client.export_jsonl()
for entry in entries:
    print(entry.instruction, entry.input, entry.output)
```

### Async client

A fully async client is available with the same interface:

```python
import asyncio
from threat_feed_client import AsyncThreatFeedClient

async def main():
    async with AsyncThreatFeedClient() as client:
        feeds = await client.list_threat_feeds(per_page=10)
        for feed in feeds:
            print(feed.title)

        # Async auto-pagination
        async for feed in client.iter_threat_feeds(severity="high"):
            process(feed)

asyncio.run(main())
```

## API reference

### Client methods

| Method | Description |
|--------|-------------|
| `list_threat_feeds(**filters)` | Paginated list of threat feeds |
| `get_threat_feed(uuid)` | Single threat feed by UUID |
| `iter_threat_feeds(**filters)` | Auto-paginating iterator |
| `export_json()` | Export all feeds as JSON |
| `export_jsonl()` | Export as instruction-tuning entries |
| `list_vulnerabilities(**filters)` | Paginated list of vulnerabilities (admin) |
| `get_vulnerability(uuid)` | Single vulnerability by UUID (admin) |
| `update_vulnerability(uuid, **fields)` | Update vulnerability fields (admin) |
| `iter_vulnerabilities(**filters)` | Auto-paginating iterator (admin) |
| `match_prompt(prompt)` | Match prompt against signatures (sdk_access) |
| `create_comment(uuid, text, internal=False)` | Add comment to vulnerability (admin) |
| `update_comment(uuid, comment_id, text)` | Edit a comment (admin) |
| `list_models(**filters)` | Paginated list of AI models (researcher) |
| `get_model(model_id)` | Single model by ID (researcher) |
| `iter_models(**filters)` | Auto-paginating iterator (researcher) |
| `list_attacks(**filters)` | Paginated list of attacks (admin) |
| `get_attack(attack_id)` | Single attack by ID (admin) |

### Filter parameters

**Threat feed / vulnerability filters:**
- `severity` — `"low"`, `"medium"`, `"high"`, `"severe"`
- `security_boundary` — `"guardrail_jailbreak"`, `"prompt_extraction"`, `"interpreter_jailbreak"`, `"content_manipulation"`, `"weights_and_layers_disclosure"`, `"prompt_injection"`, `"other"`
- `states` — list of states, e.g. `["published", "disclosed"]`
- `title_contains` — substring search on title
- `uuid_start` — UUID prefix match
- `model_ids` — list of model IDs
- `taxonomy_category_id`, `taxonomy_strategy_id`, `taxonomy_technique_id` — taxonomy filters
- `page`, `per_page` — pagination (per_page max 100)

**Vulnerability-only filters:**
- `keyword` — full-text keyword search
- `assignee_id`, `submitter_id` — filter by user ID
- `search_group` — `"open"`, `"closed"`, `"validated"`, `"needs_payment"`, `"paid"`

**Model filters:**
- `name_contains` — model name substring
- `vendor_name_contains` — vendor name substring
- `model_id` — exact model ID

### Exceptions

```python
from threat_feed_client import (
    OdinAPIError,           # Base exception for all API errors
    AuthenticationError,    # Missing or invalid token
    NotFoundError,          # Resource not found (also returned for auth failures)
    RateLimitError,         # HTTP 429 - rate limit exceeded
    ValidationError,        # HTTP 422 - invalid request data
    ServiceUnavailableError # HTTP 503 - upstream service down
)
```

### Data models

All responses are parsed into typed [Pydantic v2](https://docs.pydantic.dev/) models with full IDE autocompletion. Key types:

- `ThreatFeed` — uuid, title, summary, detail, severity, security_boundary, models, messages, taxonomies, test_results, detection_signatures, metadata, reference_urls, variant_prompts
- `Vulnerability` — all ThreatFeed fields plus aasm_state, bounty_amount, awarded, assignee_id, submitter_id, feed (activity log), duplicates
- `Attack` — vulnerability reference, techniques, messages, text_anchors
- `AIModel` — id, name, retired, vendor
- `MatchResult` — duplicate_probability, signature_version, matches
- `Comment` — id, comment, internal, timestamps
- `PaginatedResponse[T]` — items, page, total_pages, total_count, has_next_page

## Development

```bash
uv sync                 # install all dependencies
uv run pytest -v        # run tests
uv run ruff check src/  # lint
```
