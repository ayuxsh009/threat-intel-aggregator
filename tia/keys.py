"""API key and API token resolution that works without Streamlit.

The Streamlit app reads secrets through ``st.secrets``; the browser-extension
API server reads the same ``secrets.toml`` file directly. Both resolve keys
with the same precedence: secrets > environment variables > app settings.
"""

from __future__ import annotations

import os
import secrets as _secrets
from pathlib import Path

from .config import BASE_DIR

# key -> (label, name in [apikeys] secrets, environment variable)
KEY_FIELDS = {
    "vt": ("VirusTotal", "VT", "VT_API_KEY"),
    "abuseipdb": ("AbuseIPDB", "AbuseIPDB", "ABUSEIPDB_API_KEY"),
    "shodan": ("Shodan", "Shodan", "SHODAN_API_KEY"),
    "abusech": ("abuse.ch", "AbuseCH", "ABUSECH_API_KEY"),
}

TOKEN_SETTING = "api.token"
TOKEN_ENV = "TI_API_TOKEN"


def secrets_paths() -> list[Path]:
    return [Path.home() / ".streamlit" / "secrets.toml", BASE_DIR / ".streamlit" / "secrets.toml"]


def load_secrets_file() -> dict:
    """Merge the global and project secrets files (project wins). Missing or invalid files are ignored."""
    try:
        import toml
    except ImportError:  # pragma: no cover - toml ships with Streamlit
        return {}
    merged: dict = {}
    for path in secrets_paths():
        try:
            if path.is_file():
                merged.update(toml.load(str(path)))
        except Exception:
            continue
    return merged


def resolve(store, apikeys_section: dict) -> dict[str, tuple[str, str]]:
    """Return ``{key: (value, origin)}``. ``apikeys_section`` is the [apikeys] table of the secrets."""
    out = {}
    for key, (_, secret_name, env) in KEY_FIELDS.items():
        if apikeys_section.get(secret_name):
            out[key] = (str(apikeys_section[secret_name]), "secrets")
        elif os.environ.get(env):
            out[key] = (os.environ[env], "environment")
        elif store.get_setting(f"apikey.{key}"):
            out[key] = (store.get_setting(f"apikey.{key}"), "app settings")
        else:
            out[key] = ("", "not set")
    return out


def api_token(store, secrets_data: dict | None = None, *, create: bool = True) -> tuple[str, str]:
    """Token the browser extension must send. Returns ``(token, origin)``.

    Precedence: ``TI_API_TOKEN`` env var > ``[api] token`` in secrets > app setting.
    A random token is generated and stored on first use.
    """
    if os.environ.get(TOKEN_ENV):
        return os.environ[TOKEN_ENV], "environment"
    section = (secrets_data or {}).get("api") or {}
    if section.get("token"):
        return str(section["token"]), "secrets"
    token = store.get_setting(TOKEN_SETTING)
    if not token and create:
        token = new_token(store)
    return token, "app settings" if token else "not set"


def new_token(store) -> str:
    token = _secrets.token_urlsafe(24)
    store.set_setting(TOKEN_SETTING, token)
    return token
