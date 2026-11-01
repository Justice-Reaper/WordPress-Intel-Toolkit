#!/usr/bin/env python3
"""Run the collectors and build combined WordPress slug dictionaries."""

import argparse
import sys
from pathlib import Path
from importlib import import_module

from common.scraper_common import progress_log, argument_parser, add_browser_arguments, run_cli, add_request_arguments, client_from_args, save_slugs


BASE = Path(__file__).parent
SOURCES = {
    "wordpress-org": ("dictionaries.wordpress_org_dictionaries", "wordpress-org-http-errors.log"),
    "wordfence": ("dictionaries.wordfence_dictionaries", "wordfence-http-non-200.log"),
    "wpscan": ("dictionaries.wpscan_dictionaries", "wpscan-http-errors.log"),
    "patchstack": ("dictionaries.patchstack_dictionaries", "patchstack-http-errors.log"),
}
SOURCE_NAMES = {
    "wordpress-org": "WordPress.org",
    "wordfence": "Wordfence",
    "wpscan": "WPScan",
    "patchstack": "Patchstack",
}


def parse_sources(value):
    selected = [name.strip() for name in value.split(",") if name.strip()]
    unknown = sorted(set(selected) - SOURCES.keys())
    if not selected or unknown:
        valid = ", ".join(SOURCES)
        raise argparse.ArgumentTypeError(
            f"Invalid source(s): {', '.join(unknown) or value}. Valid options: {valid}"
        )
    return list(dict.fromkeys(selected))


def main():
    parser = argument_parser()
    parser.add_argument_group("Sources").add_argument(
        "--sources", type=parse_sources, metavar="SOURCE,SOURCE,...",
        default=list(SOURCES),
        help=(
            "Sources: wordpress-org, wordfence, wpscan, patchstack (comma-separated; default: all)"
        ),
    )
    add_request_arguments(parser)
    add_browser_arguments(parser, patchstack_dictionaries=True)
    args = parser.parse_args()

    merged = {"plugins": set(), "themes": set()}
    wordpress_order = {"plugins": [], "themes": []}
    for name in args.sources:
        module_name, log_name = SOURCES[name]
        print(f"\n=== {SOURCE_NAMES[name]} ===", file=sys.stderr, flush=True)
        client = client_from_args(args, BASE / log_name)
        try:
            module = import_module(module_name)
            result = module.collect(client)
        except ImportError as error:
            progress_log.failure(f"{name}: missing dependency {error.name}; follow the README setup instructions")
            raise SystemExit(1)
        except (RuntimeError, ValueError, OSError) as error:
            progress_log.failure(f"{name}: {error}")
            raise SystemExit(1)
        for kind in merged:
            merged[kind].update(result[kind])
            if name == "wordpress-org":
                wordpress_order[kind] = list(result[kind])

    try:
        print(file=sys.stderr, flush=True)
        print("=== Results ===", file=sys.stderr, flush=True)
        for kind, slugs in merged.items():
            ordered = wordpress_order[kind] + sorted(slugs.difference(wordpress_order[kind]))
            save_slugs(BASE / "combined" / kind / "slugs.txt", ordered, preserve_order=True)
    except (ValueError, OSError) as error:
        progress_log.failure(f"Could not save combined dictionaries: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    run_cli(main)
