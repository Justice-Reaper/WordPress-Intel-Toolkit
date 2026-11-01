#!/usr/bin/env python3
"""Query WordPress vulnerabilities across the selected public sources."""

import argparse
import re
import sys
from importlib import import_module

from common.output import announce_saved_report, new_report_path, save_report_checkpoint
from common.scraper_common import progress_log, validate_version_threshold, argument_parser, add_browser_arguments, add_request_arguments, client_from_args, run_cli


SOURCES = {
    "patchstack": "vulnerabilities.sources.patchstack",
    "wordfence": "vulnerabilities.sources.wordfence",
    "wpscan": "vulnerabilities.sources.wpscan",
}


def parse_sources(value):
    selected = list(dict.fromkeys(name.strip() for name in value.split(",") if name.strip()))
    unknown = set(selected) - SOURCES.keys()
    if not selected or unknown:
        raise argparse.ArgumentTypeError("Sources must be patchstack, wordfence, or wpscan, separated by commas")
    return selected


def main():
    parser = argument_parser()
    targets = parser.add_argument_group("Target (choose one)").add_mutually_exclusive_group(required=True)
    targets.add_argument("--plugin", metavar="SLUG", help="Plugin slug to query")
    targets.add_argument("--theme", metavar="SLUG", help="Theme slug to query")
    targets.add_argument("--core-version", dest="core", metavar="VERSION", help="WordPress Core version threshold")
    parser.add_argument_group("Version filter").add_argument("--version", metavar="VERSION",
                        help="Minimum affected-version threshold (required with --plugin or --theme)")
    parser.add_argument_group("Sources").add_argument("--sources", type=parse_sources, default=list(SOURCES), metavar="SOURCE,SOURCE,...",
                        help="Sources: patchstack, wordfence, wpscan (default: all)")
    add_request_arguments(parser)
    add_browser_arguments(parser, patchstack_core=True)
    args = parser.parse_args()
    kind, target = next((kind, getattr(args, kind)) for kind in ("plugin", "theme", "core") if getattr(args, kind) is not None)
    if kind == "core":
        if not re.fullmatch(r"\d+(?:\.\d+){1,3}", target):
            parser.error("Core version must be numeric, for example 6.8.5")
    elif not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", target, re.I):
        parser.error("Slug must contain only letters, numbers, dots, underscores, and hyphens")
    if kind == "core" and args.version is not None:
        parser.error("Use --core-version VERSION without --version")
    if kind != "core" and args.version is None:
        parser.error("--version is required with --plugin or --theme")
    try:
        threshold = validate_version_threshold(target if kind == "core" else args.version)
    except ValueError as error:
        parser.error(str(error))
    results, errors = {}, {}
    output = {"product_type": kind, "version": threshold, "sources": results, "errors": errors, "complete": False, "pending_sources": list(args.sources)}
    if kind != "core":
        output["slug"] = target
    for index, source in enumerate(args.sources, start=1):
        source_name = {"wordfence": "Wordfence", "wpscan": "WPScan", "patchstack": "Patchstack"}[source]
        print(f"\n=== {source_name} ===", file=sys.stderr, flush=True)
        client = client_from_args(args, None)
        source_report = {"source": source_name, "product_type": kind, "version": threshold,
                         "vulnerabilities": [], "errors": [], "complete": False}
        if kind != "core":
            source_report["slug"] = target
        try:
            module = import_module(SOURCES[source])
            if source == "wordfence":
                result = module.lookup(kind, target, client, version=threshold)
            elif kind == "core":
                result = module.fetch_core(client, target)
            else:
                result = module.fetch_product(client, kind, target, threshold)
            source_report.update(result)
            results[source] = source_report
            if not result.get("complete", True):
                errors[source] = f"Partial result: {len(result.get('errors', []))} detail pages failed; collected vulnerabilities are preserved"
                progress_log.warning(f"Source {source}: {errors[source]}")
        except (RuntimeError, ValueError, OSError, ImportError) as error:
            errors[source] = str(error)
            source_report["errors"] = [{"error": str(error)}]
            progress_log.failure(f"Source {source} failed: {error}")
        report_path = new_report_path(source_report)
        if save_report_checkpoint(source_report, report_path):
            announce_saved_report(report_path)
        else:
            message = f"Could not save {source_name} report to {report_path}; the combined report will still be attempted"
            errors[source] = f"{errors[source]}; {message}" if source in errors else message
        output["pending_sources"] = args.sources[index:]
        output["complete"] = not errors and not output["pending_sources"]
    print("=== Results ===", file=sys.stderr, flush=True)
    final_path = new_report_path(output)
    saved = save_report_checkpoint(output, final_path)
    if saved:
        announce_saved_report(final_path)
    else:
        output["complete"] = False
    if errors or not saved:
        raise SystemExit(1)


if __name__ == "__main__":
    run_cli(main)
