"""UI tests using Streamlit's headless AppTest runner.

The entry script (login / first-run setup) is tested as a whole. Streamlit 1.40's
AppTest does not execute pages registered through st.navigation, so each page
script under views/ is run directly with a signed-in session seeded in state.
Navigation itself is checked in a real browser (see DOCUMENTATION.md, Testing).
"""

from unittest import mock

import pytest
from streamlit.testing.v1 import AppTest

from tia import auth, sources
from tia.storage import Store

from conftest import ROOT

APP = str(ROOT / "streamlit_app.py")
PAGES = ["views/dashboard.py", "views/analytics.py", "views/scan.py",
         "views/investigations.py", "views/reports.py", "views/settings.py"]

VT_HIT = {"ok": True, "found": True, "malicious": 14, "suspicious": 1, "harmless": 50, "undetected": 5,
          "total": 70, "detections": [{"engine": "E1", "category": "malicious", "result": "trojan"}], "tags": []}
VT_CLEAN = {"ok": True, "found": True, "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 0,
            "total": 70, "detections": [], "tags": []}
ABUSE = {"ok": True, "confidence": 100, "reports": 120, "whitelisted": False, "country": "DE"}
SHODAN = {"ok": True, "found": True, "ports": [22, 443], "org": "ACME", "vulns": [], "hostnames": []}


def fake_vt(ioc, key, **kw):
    return VT_HIT if "evil" in ioc or ioc.startswith("185.") else VT_CLEAN


@pytest.fixture
def patched_sources():
    with mock.patch.object(sources, "query_virustotal", side_effect=fake_vt), \
         mock.patch.object(sources, "query_abuseipdb", return_value=ABUSE), \
         mock.patch.object(sources, "query_shodan", return_value=SHODAN):
        yield


def new_app():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def click(at, label):
    [b for b in at.button if b.label == label][0].click()
    at.run()


def assert_ok(at):
    assert not at.exception, [e.value for e in at.exception]


def login(at, user, pw):
    at.text_input[0].input(user)
    at.text_input[1].input(pw)
    click(at, "Sign in")


def test_first_run_creates_admin(data_dir):
    at = new_app()
    assert_ok(at)
    assert any("Create account" == b.label for b in at.button)
    at.text_input[0].input("admin")
    at.text_input[1].input("short")
    at.text_input[2].input("short")
    click(at, "Create account")
    assert any("at least" in e.value for e in at.error)

    at.text_input[1].input("Str0ng-pass")
    at.text_input[2].input("Str0ng-pass")
    click(at, "Create account")
    assert_ok(at)
    assert at.session_state["user"]["role"] == "admin"
    stored = Store(data_dir / "threatintel.db").get_user("admin")
    assert stored["password_hash"].startswith("pbkdf2_sha256$")


def test_login_and_lockout(data_dir):
    Store(data_dir / "threatintel.db").add_user("alice", auth.hash_password("alice-pass-1"), "analyst")
    at = new_app()
    login(at, "alice", "wrong")
    assert any("Invalid" in e.value for e in at.error)
    for _ in range(4):
        login(at, "alice", "wrong")
    assert any("paused" in e.value for e in at.error)
    login(at, "alice", "alice-pass-1")          # still locked
    assert "user" not in at.session_state
    at.session_state["lock_until"] = 0
    login(at, "alice", "alice-pass-1")
    assert at.session_state["user"]["username"] == "alice"


def page(data_dir, path, role="admin", state=None):
    """Run one page script as a signed-in user."""
    store = Store(data_dir / "threatintel.db")
    if not store.get_user("tester"):
        store.add_user("tester", auth.hash_password("tester-pass-1"), role)
    at = AppTest.from_file(str(ROOT / path), default_timeout=60)
    at.session_state["user"] = {"username": "tester", "role": role, "source": "local", "insecure": False}
    for k, v in (state or {}).items():
        at.session_state[k] = v
    at.run()
    assert_ok(at)
    return at


def test_entry_shows_navigation_when_signed_in(data_dir):
    Store(data_dir / "threatintel.db").add_user("tester", auth.hash_password("tester-pass-1"), "admin")
    at = AppTest.from_file(APP, default_timeout=60)
    at.session_state["user"] = {"username": "tester", "role": "admin", "source": "local", "insecure": False}
    at.run()
    assert_ok(at)
    assert any(b.label == "Sign out" for b in at.button)


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders_empty(data_dir, path):
    page(data_dir, path)


def test_single_scan_flow(data_dir, patched_sources):
    at = page(data_dir, "views/scan.py")
    at.text_input[0].input("185.220.101[.]8")
    click(at, "Scan")
    assert_ok(at)
    result = at.session_state["single_result"]
    assert result["ioc"] == "185.220.101.8" and result["risk"] == "High"
    assert any("Open in VirusTotal" in m.value or "VirusTotal" in m.value for m in at.markdown)
    assert len(Store(data_dir / "threatintel.db").scans()) == 1
    for path in PAGES:  # every page with data present
        page(data_dir, path)


def test_paste_batch_flow(data_dir, patched_sources):
    at = page(data_dir, "views/scan.py")
    at.text_area[0].input("\n".join(["evil[.]com", "example.com", "8.8.8.8", "10.0.0.1", "example.com"]))
    at.run()
    click(at, "Scan list")
    assert_ok(at)
    batch = at.session_state["batch_result"]["results"]
    # 8.8.8.8 is High only because the fake AbuseIPDB always answers 100%
    assert [r["risk"] for r in batch] == ["High", "Legitimate", "High", "Unknown"]
    assert len(at.dataframe) >= 1


def test_investigation_row_selection_shows_detail(data_dir, patched_sources):
    at = page(data_dir, "views/scan.py")
    at.text_input[0].input("evil.com")
    click(at, "Scan")
    at = page(data_dir, "views/investigations.py")
    assert len(at.dataframe) == 1
    assert any("1 of 1" in c.value for c in at.caption)


def test_reports_generate_pdf(data_dir, patched_sources):
    at = page(data_dir, "views/scan.py")
    at.text_input[0].input("evil.com")
    click(at, "Scan")
    at = page(data_dir, "views/reports.py")
    click(at, "Generate PDF")
    assert_ok(at)
    pdf = [v for k, v in at.session_state.filtered_state.items() if k.startswith("pdf_")][0]
    assert pdf["bytes"].startswith(b"%PDF")
    assert any(b.label == "Download PDF" for b in at.get("download_button"))


def test_settings_save_keys_and_add_user(data_dir):
    at = page(data_dir, "views/settings.py")
    [t for t in at.text_input if t.label == "VirusTotal API key"][0].input("NEW-VT-KEY")
    click(at, "Save keys")
    assert_ok(at)
    store = Store(data_dir / "threatintel.db")
    assert store.get_setting("apikey.vt") == "NEW-VT-KEY"

    [t for t in at.text_input if t.label == "Username"][0].input("dana")
    [t for t in at.text_input if t.label == "Temporary password"][0].input("dana-pass-1")
    click(at, "Add user")
    assert_ok(at)
    assert store.get_user("dana")["role"] == "analyst"


def test_change_password(data_dir):
    at = page(data_dir, "views/settings.py")
    [t for t in at.text_input if t.label == "Current password"][0].input("tester-pass-1")
    [t for t in at.text_input if t.label == "New password"][0].input("brand-new-pass-2")
    [t for t in at.text_input if t.label == "Confirm new password"][0].input("brand-new-pass-2")
    click(at, "Update password")
    assert any("updated" in s.value for s in at.success)
    assert auth.authenticate(Store(data_dir / "threatintel.db"), "tester", "brand-new-pass-2")


def test_analyst_restrictions(data_dir):
    store = Store(data_dir / "threatintel.db")
    sid = store.create_session("someone-else", "single", "x")
    store.add_scan(sid, "someone-else", {"ioc": "other.com", "risk": "High", "type": "Domain",
                                         "timestamp": "2026-01-01T10:00:00"})
    at = page(data_dir, "views/settings.py", role="analyst")
    assert all(t.disabled for t in at.text_input if t.label.endswith("API key"))
    assert "Users" not in [t.label for t in at.tabs]
    at = page(data_dir, "views/investigations.py", role="analyst")
    assert len(at.dataframe) == 0                       # cannot see another user's scans
    at = page(data_dir, "views/investigations.py", role="admin")
