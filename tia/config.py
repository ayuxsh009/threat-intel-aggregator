"""Application-wide constants and paths."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Threat Intel Aggregator"
APP_VERSION = "2.0.0"

BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"


def data_dir() -> Path:
    """Directory for the SQLite database. Override with the TI_DATA_DIR env var."""
    return Path(os.environ.get("TI_DATA_DIR") or (BASE_DIR / "data"))


def db_path() -> Path:
    return data_dir() / "threatintel.db"


# Ordered from most to least severe; "Unknown" means no source returned data.
RISK_ORDER = ["High", "Medium", "Low", "Legitimate", "Unknown"]

RISK_COLORS = {
    "High": "#ef4444",
    "Medium": "#f97316",
    "Low": "#eab308",
    "Legitimate": "#22c55e",
    "Unknown": "#64748b",
}

RISK_ICONS = {
    "High": "🔴",
    "Medium": "🟠",
    "Low": "🟡",
    "Legitimate": "🟢",
    "Unknown": "⚪",
}
