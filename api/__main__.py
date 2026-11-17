"""Command line for the extension API.

    python -m api                     start the server on 127.0.0.1:8600
    python -m api --port 9000         another port
    python -m api --host 0.0.0.0      listen on all interfaces (put it behind HTTPS!)
    python -m api token               print the token to paste into the extension
    python -m api token --new         replace the token (the extension must be updated)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tia import config, keys  # noqa: E402
from tia.storage import Store  # noqa: E402


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="python -m api", description=f"{config.APP_NAME} extension API")
    parser.add_argument("command", nargs="?", choices=["serve", "token"], default="serve")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8600)
    parser.add_argument("--new", action="store_true", help="with 'token': generate a new token")
    args = parser.parse_args(argv)

    store = Store(config.db_path())
    if args.command == "token":
        if args.new:
            print(keys.new_token(store))
        else:
            token, origin = keys.api_token(store, keys.load_secrets_file())
            print(token)
            print(f"(from {origin})", file=sys.stderr)
        return

    import uvicorn

    from api.server import create_app

    token, origin = keys.api_token(store, keys.load_secrets_file())
    print(f"{config.APP_NAME} API on http://{args.host}:{args.port}")
    print(f"Extension token ({origin}): {token}")
    if args.host not in ("127.0.0.1", "localhost"):
        print("Warning: listening beyond this machine. Use HTTPS (a reverse proxy) and keep the token secret.")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
