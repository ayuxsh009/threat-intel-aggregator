"""Pull indicators out of free text: emails, logs, alerts, threat reports.

Handles defanged notation (hxxp, [.], (dot), [:]) and filters the usual noise:
file names that look like domains, XML namespace hosts, private IPs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .ioc import _DOT, normalize

# Extensions that make "invoice.pdf" look like a domain. Some are real TLDs
# (.zip, .mov), but in reports they are almost always file names.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "msi", "jar", "py", "sh",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt", "log", "csv", "json", "xml",
    "yml", "yaml", "ini", "cfg", "conf", "html", "htm", "php", "asp", "aspx", "png", "jpg", "jpeg", "gif", "bmp",
    "svg", "ico", "zip", "rar", "7z", "gz", "tar", "iso", "img", "bin", "dat", "tmp", "bak", "eml", "msg", "mov",
    "mp4", "mp3", "wav", "db", "sqlite", "pem", "crt", "key", "md",
}
NOISE_DOMAINS = {
    "w3.org", "www.w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org",
    "ns.adobe.com", "xmlns.com", "schema.org", "example.com", "example.org", "example.net",
}

_HXXP = re.compile(r"\bh(?:xx|XX|\*\*)p(s?)(?:\[:\]|:)//", re.I)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`]+", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)")
_HASH = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
_DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
_TRAILING = ".,;:!?)]}>'\""


def refang_text(text: str) -> str:
    s = text or ""
    s = s.replace("[://]", "://").replace("[:]", ":").replace("[/]", "/")
    s = _HXXP.sub(lambda m: f"http{m.group(1)}://", s)
    return _DOT.sub(".", s)


def _clean_url(url: str) -> str:
    url = url.rstrip(_TRAILING)
    # Balance a trailing ")" that belonged to surrounding prose.
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    return url


def extract(text: str, *, include_private: bool = False) -> list[dict]:
    """Return unique indicators in order of appearance: ``[{"ioc", "type"}]``."""
    s = refang_text(text)
    found: list[tuple[int, str, str]] = []

    for m in _URL.finditer(s):
        url = _clean_url(m.group(0))
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in NOISE_DOMAINS:
            found.append((m.start(), url, "URL"))
    # Blank out URLs so their hosts are not reported twice.
    masked = _URL.sub(lambda m: " " * len(m.group(0)), s)

    for m in _HASH.finditer(masked):
        ioc, kind = normalize(m.group(0))
        found.append((m.start(), ioc, kind))
    masked = _HASH.sub(lambda m: " " * len(m.group(0)), masked)

    for m in _IPV4.finditer(masked):
        ip = m.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if include_private or addr.is_global:
            found.append((m.start(), str(addr), "IP"))
    masked = _IPV4.sub(lambda m: " " * len(m.group(0)), masked)

    for m in _DOMAIN.finditer(masked):
        domain = m.group(0).lower().rstrip(".")
        tld = domain.rsplit(".", 1)[-1]
        if tld in FILE_EXTENSIONS or domain in NOISE_DOMAINS or tld.isdigit():
            continue
        found.append((m.start(), domain, "Domain"))

    seen: set[str] = set()
    out = []
    for _, ioc, kind in sorted(found, key=lambda x: x[0]):
        key = ioc.lower()
        if key not in seen:
            seen.add(key)
            out.append({"ioc": ioc, "type": kind})
    return out
