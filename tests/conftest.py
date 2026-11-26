from datetime import UTC, datetime
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def now() -> datetime:
    return NOW
