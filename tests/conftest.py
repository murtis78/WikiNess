from pathlib import Path

import pytest

from wikiness.storage import init_schema, open_db

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def db(tmp_path):
    conn = open_db(tmp_path / "test.db")
    init_schema(conn)
    yield conn
    conn.close()
