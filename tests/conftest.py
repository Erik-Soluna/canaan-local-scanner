import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _ensure_sqlite_schema() -> None:
    """Create any missing tables (e.g. after adding a model) before TestClient runs."""
    from app import models  # noqa: F401
    from app.db import ENGINE, Base

    Base.metadata.create_all(ENGINE)
