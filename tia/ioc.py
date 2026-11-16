"""IOC normalisation (refanging) and type detection."""

from __future__ import annotations

import ipaddress
import re

HASH_TYPES = {32: "MD5", 40: "SHA1", 64: "SHA256"}

_HEX = re.compile(r"^[A-Fa-f0-9]+$")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.I)
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_DOT = re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I)
_HXXP = re.compile(r"^h(?:xx|\*\*|XX)p(s?)(\[?:\]?)//", re.I)
_SPLIT = re.compile(r"[\s,;]+")


def refang(value: str) -> str:
    """Turn defanged indicators back into real ones.

    Handles hxxp://, [.], (.), {.}, [dot], [:], [://] and [/].
    """
    s = (value or "").strip().strip("\"'<>")
    s = s.replace("[://]", "://").replace("[:]", ":").replace("[/]", "/")
    s = _HXXP.sub(lambda m: f"http{m.group(1)}://", s)
    s = _DOT.sub(".", s)
    return s


def classify(value: str) -> str:
    """Return MD5, SHA1, SHA256, IP, URL, Domain or Unknown."""
    s = (value or "").strip()
    if not s:
        return "Unknown"
    if _HEX.match(s) and len(s) in HASH_TYPES:
        return HASH_TYPES[len(s)]
    try:
        ipaddress.ip_address(s)
        return "IP"
    except ValueError:
        pass
    if _URL.match(s):
        return "URL"
    if _DOMAIN.match(s.rstrip(".")):
        return "Domain"
    return "Unknown"


def normalize(value: str) -> tuple[str, str]:
    """Refang, classify and canonicalise an indicator. Returns (ioc, type)."""
    s = refang(value)
    kind = classify(s)
    if kind == "Domain":
        s = s.lower().rstrip(".")
    elif kind in HASH_TYPES.values():
        s = s.lower()
    elif kind == "IP":
        s = str(ipaddress.ip_address(s))
    return s, kind


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def parse_list(text: str) -> list[str]:
    """Split pasted text into unique, refanged indicators (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for token in _SPLIT.split(text or ""):
        if not token.strip():
            continue
        ioc, _ = normalize(token)
        if ioc and ioc not in seen:
            seen.add(ioc)
            out.append(ioc)
    return out
