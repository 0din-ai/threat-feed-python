import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    return FIXTURES_DIR


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())
