"""Create a browser authentication state for a configured test identity."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from playwright.async_api import async_playwright

from src.discovery import auth
from src.discovery.crawler import get_origin_output_dir

logging.basicConfig(level=logging.INFO, format="%(message)s")


async def create_state(identity: str, output: Path, origin: str | None) -> bool:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            return await auth.create_auth_state(
                browser,
                identity,
                output,
                target_origin=origin,
                errors_path=auth.ERRORS_PATH,
            )
        finally:
            await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a browser authentication state for an IDOR test identity",
    )
    parser.add_argument(
        "--identity",
        choices=("victim", "attacker"),
        required=True,
        help="Configured identity to authenticate",
    )
    parser.add_argument("--output", type=Path, help="Override the configured state path")
    parser.add_argument(
        "--origin",
        help="Target origin used to resolve a relative LOGIN_URL",
    )
    args = parser.parse_args()

    _, _, configured_path = auth.get_identity_settings(args.identity)
    if args.output:
        output = args.output.expanduser()
    elif args.origin:
        output = get_origin_output_dir(args.origin) / f"auth_state_{args.identity}.json"
    else:
        output = configured_path.expanduser()
    if not output.is_absolute():
        output = auth.ROOT / output
    succeeded = asyncio.run(create_state(args.identity, output, args.origin))
    if not succeeded:
        raise SystemExit(f"Could not create {args.identity} authentication state")
    if args.origin:
        auth.write_auth_metadata(
            output.with_name(f"{output.stem}.metadata.json"),
            args.origin,
        )
    logging.info("Saved %s authentication state to %s", args.identity, output)


if __name__ == "__main__":
    main()
