"""Password hashing (PBKDF2-SHA256, standard library only) and login checks.

Generate a hash for ``.streamlit/secrets.toml`` with::

    python -m tia.auth
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import re
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 260_000
ROLES = ("admin", "analyst")
MIN_PASSWORD_LENGTH = 8

_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def hash_password(password: str, *, iterations: int = ITERATIONS, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"{ALGORITHM}${iterations}${salt}${digest.hex()}"


_DUMMY_HASH = hash_password("dummy-password", iterations=ITERATIONS, salt="0" * 32)


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, digest = str(stored).split("$")
        if algorithm != ALGORITHM:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc.hex(), digest)


def validate_username(username: str) -> str | None:
    if not _USERNAME.match(username or ""):
        return "Username must be 3-32 characters: letters, digits, '.', '_' or '-'."
    return None


def validate_password(password: str) -> str | None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if password.isdigit() or password.isalpha():
        return "Use a mix of letters and numbers or symbols."
    return None


def authenticate(store, username: str, password: str, secret_users=()) -> dict | None:
    """Check local (database) users, then users defined in Streamlit secrets.

    Returns ``{"username", "role", "source", "insecure"}`` or ``None``.
    """
    username = (username or "").strip()
    if not username or not password:
        return None

    user = store.get_user(username)
    if user:
        if verify_password(password, user["password_hash"]):
            return {"username": user["username"], "role": user["role"], "source": "local", "insecure": False}
        return None

    for su in secret_users or ():
        if str(su.get("username", "")).lower() != username.lower():
            continue
        role = su.get("role", "admin") if su.get("role", "admin") in ROLES else "analyst"
        if su.get("password_hash") and verify_password(password, su["password_hash"]):
            return {"username": su["username"], "role": role, "source": "secrets", "insecure": False}
        if su.get("password") is not None and hmac.compare_digest(
            str(su["password"]).encode("utf-8"), password.encode("utf-8")
        ):
            # Plain-text passwords in secrets still work, but the UI warns about them.
            return {"username": su["username"], "role": role, "source": "secrets", "insecure": True}
        return None

    verify_password(password, _DUMMY_HASH)  # keep timing similar for unknown users
    return None


def main() -> None:
    pw = getpass.getpass("Password to hash: ")
    if getpass.getpass("Repeat password: ") != pw:
        raise SystemExit("Passwords do not match.")
    problem = validate_password(pw)
    if problem:
        raise SystemExit(problem)
    print(hash_password(pw))


if __name__ == "__main__":
    main()
