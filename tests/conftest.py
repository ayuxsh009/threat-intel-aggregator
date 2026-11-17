import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


from tia import sources  # noqa: E402

REAL_QUERY_RDAP = sources.query_rdap


@pytest.fixture(autouse=True)
def no_rdap_network(monkeypatch):
    """RDAP needs no key, so scans would call it for real; stub it in every test."""
    monkeypatch.setattr(sources, "query_rdap", lambda domain, **kw: {"ok": True, "found": False, "domain": domain})


@pytest.fixture(autouse=True)
def ignore_local_secrets(monkeypatch):
    """A developer's real .streamlit/secrets.toml must not leak users or keys into tests."""
    from tia.ui import common
    monkeypatch.setattr(common, "_has_secrets", lambda: False)


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Point the app at an empty, throwaway data directory."""
    monkeypatch.setenv("TI_DATA_DIR", str(tmp_path / "data"))
    for var in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "ABUSECH_API_KEY", "TI_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path / "data"


@pytest.fixture
def store(data_dir):
    from tia.storage import Store
    return Store(data_dir / "test.db")


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = str(self._payload)

    def json(self):
        return self._payload


@pytest.fixture
def fake_response():
    return FakeResponse
