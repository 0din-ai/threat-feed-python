# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.0.1] - 2026-05-19

### Added

- `ThreatFeedClient` (sync) and `AsyncThreatFeedClient` (async) covering all 14 API endpoints
- Threat feed endpoints: list, get, export JSON, export JSONL
- Vulnerability endpoints: list, get, update (admin)
- Prompt signature matching endpoint (sdk_access)
- Comment endpoints: create, update (admin)
- Model endpoints: list, get (researcher)
- Attack endpoints: list, get (admin)
- Auto-paginating iterators (`iter_threat_feeds`, `iter_vulnerabilities`, `iter_models`)
- Pythonic filter API mapping to Ransack query syntax
- Typed Pydantic v2 data models for all API responses
- Retry with exponential backoff for transient errors
- `.env` file support via python-dotenv
- 52 unit tests with full coverage of all endpoints and error handling
