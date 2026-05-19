# threat-feed-client

**IMPORTANT: NEVER read, cat, print, or otherwise access the `.env` file in this project. It contains secrets (API tokens, keys). Do not read it directly, do not print its contents or partial contents, and do not use tools to inspect it. The client loads it automatically via python-dotenv.**

Python client library for the 0DIN Threat Feed API. Used internally by the ML engineering team to build downstream systems on top of the Threat Feed data (verified LLM jailbreak and prompt injection attacks).

## Quick start

```bash
uv sync              # install dependencies
uv run pytest        # run tests
uv run ruff check    # lint
```

## Project structure

```
src/threat_feed_client/
  client.py           # ThreatFeedClient (sync) - main entry point
  async_client.py     # AsyncThreatFeedClient (async mirror)
  _base.py            # Auth, URL resolution, Ransack query param mapping
  _pagination.py      # PaginatedResponse[T] generic container
  exceptions.py       # OdinAPIError, NotFoundError, RateLimitError, etc.
  models/             # Pydantic v2 data models
    enums.py          # Severity, SecurityBoundary, AasmState, Interface, Source
    threat_feed.py    # ThreatFeed and nested types (messages, taxonomies, etc.)
    vulnerability.py  # Vulnerability (admin endpoint, different serialization)
    attack.py         # Attack, TextAnchor
    model.py          # AIModel (researcher endpoint)
    match.py          # MatchResult (signature matching)
    comment.py        # Comment
    taxonomy.py       # TaxonomyTriplet (shared)
tests/
  fixtures/           # JSON response fixtures for unit tests
```

## Configuration

The client reads from a `.env` file in the working directory. Required:

- `ODIN_API_TOKEN` - JWT API token (2-part format: payload.signature)
- `ODIN_API_URL` or `ODIN_BASE_URL` - API base URL (default: `https://0din.ai/api/v1`). If the URL doesn't end in `/api/v1`, it is appended automatically.

## API endpoints covered

| Method | Endpoint | Client method | Auth required |
|--------|----------|---------------|---------------|
| GET | `/api/v1/threatfeed` | `list_threat_feeds()` | tier |
| GET | `/api/v1/threatfeed/:uuid` | `get_threat_feed()` | tier |
| GET | `/api/v1/threatfeed/export_json` | `export_json()` | tier (data_export) |
| GET | `/api/v1/threatfeed/export_jsonl` | `export_jsonl()` | tier (data_export) |
| GET | `/api/v1/vulnerabilities` | `list_vulnerabilities()` | admin |
| GET | `/api/v1/vulnerabilities/:uuid` | `get_vulnerability()` | admin |
| PATCH | `/api/v1/vulnerabilities/:uuid` | `update_vulnerability()` | admin |
| POST | `/api/v1/vulnerabilities/match` | `match_prompt()` | sdk_access |
| POST | `/api/v1/vulnerabilities/:uuid/comments` | `create_comment()` | admin |
| PATCH | `/api/v1/vulnerabilities/:uuid/comments/:id` | `update_comment()` | admin |
| GET | `/api/v1/researcher/models` | `list_models()` | researcher |
| GET | `/api/v1/researcher/models/:id` | `get_model()` | researcher |
| GET | `/api/v1/attacks` | `list_attacks()` | admin |
| GET | `/api/v1/attacks/:id` | `get_attack()` | admin |

All list methods return `PaginatedResponse[T]`. Use `iter_*` variants for auto-pagination.

## Key conventions

- The API path is `/api/v1/threatfeed` (singular, no underscore) - NOT `/api/v1/threat_feeds`
- Auth uses a raw JWT token in the `Authorization` header (no "Bearer " prefix)
- The API returns 404 for both not-found AND authentication failures
- Severity and security_boundary filters accept strings ("high", "guardrail_jailbreak") which are mapped to integer codes internally
- ThreatFeed vendor is a nested object `{name: "..."}`, but Vulnerability vendor is a flat string `"OpenAI"` - these use different model types
- Pagination: `page` + `per_page` (max 100), response includes `{page, total_pages, total_count}`

## Dependencies

- `httpx` - HTTP client (sync + async)
- `pydantic` v2 - Data models
- `tenacity` - Retry with exponential backoff
- `python-dotenv` - .env file loading

## Reference codebases

- **0DIN Platform (Rails)**: `~/0DIN/odin` - API source. Routes in `config/routes.rb`, controllers in `app/controllers/api/v1/`. Individual swagger specs in `swagger/v1/` (use `threatfeed.yaml`, `researcher.yaml` etc. - the consolidated `swagger.yaml` has incorrect paths).
- **THOR**: `~/0DIN/0din-THOR` - Legacy system with earlier API client code at `thor_sync/odin_api.py` and `odin.py`.
