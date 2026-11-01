"""Render readable vulnerability reports without changing extracted records."""

import math
import os
import re
import shutil
import textwrap
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from collections import Counter

from common.scraper_common import progress_log


FIELDS = (
    ("Title", "title"),
    ("CVE", "cve_id"),
    ("Severity", "severity"),
    ("CVSS", "cvss"),
    ("Affected versions", "affected_versions"),
    ("Patched versions", "patched_versions"),
    ("Date", "date"),
    ("Status", "status"),
    ("Software type", "software_type"),
    ("Software slug", "software_slug"),
)


SOURCE_PRIORITY = {"patchstack": 0, "wordfence": 1, "wpscan": 2}


def deduplicate_vulnerabilities(records):
    """Keep the first record from the preferred source for each valid CVE."""
    selected, seen = [], set()
    ordered = sorted(records, key=lambda item: SOURCE_PRIORITY.get(str(item[0]).strip().casefold(), len(SOURCE_PRIORITY)))
    for source, record in ordered:
        value = record.get("cve_id")
        match = re.fullmatch(r"CVE-\d{4}-\d+", value.strip(), re.I) if isinstance(value, str) else None
        if match:
            cve = match.group(0).upper()
            if cve in seen:
                continue
            seen.add(cve)
        selected.append((source, record))
    return selected


def cvss_score(value):
    """Accept only finite numeric scores in the CVSS range."""
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None


def severity(value):
    """Apply FIRST's qualitative CVSS severity bands."""
    score = cvss_score(value)
    if score is None:
        return "Unrated"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low" if score > 0 else "None"


def readable(value):
    text = " ".join(str(value).split()) if value is not None else ""
    return text or "Unknown"


def format_vulnerability_report(result, width=None, deduplicate=True):
    """Align field values with four spaces after the longest vulnerability label."""
    value_column = max(len(label) + 1 for label, _ in FIELDS) + 4
    columns = max(value_column + 1, width if width is not None else shutil.get_terminal_size(fallback=(120, 24)).columns)

    def field(label, value):
        text = readable(value)
        prefix = (label + ":").ljust(max(value_column, len(label) + 5))
        if label in {"Title", "Affected versions", "Patched versions"}:
            parts = textwrap.wrap(text, width=max(1, columns - len(prefix)), break_on_hyphens=False) or [text]
            return "\n".join([prefix + parts[0]] + [" " * len(prefix) + part for part in parts[1:]])
        return prefix + text

    sources = result.get("sources")
    reports = list(sources.items()) if isinstance(sources, dict) else [(result.get("source", "Unknown"), result)]
    records = [(report.get("source", name), record)
               for name, report in reports for record in report.get("vulnerabilities", [])]
    if deduplicate:
        records = deduplicate_vulnerabilities(records)
    records.sort(key=lambda item: cvss_score(item[1].get("cvss")) if cvss_score(item[1].get("cvss")) is not None else -1, reverse=True)
    counts = Counter(severity(record.get("cvss")) for _, record in records)
    categories = ["Critical", "High", "Medium", "Low"]
    categories.extend(name for name in ("None", "Unrated") if counts[name])
    lines = ["(" + " | ".join(f"{name}: {counts[name]}" for name in categories) + ")"]
    kind = result.get("product_type", "target")
    target = result.get("version") if kind == "core" else result.get("slug")
    lines.append(field("Version" if kind == "core" else kind.title(), target))
    if kind != "core" and result.get("version"):
        lines.append(field("Version", result["version"]))
    source_names = [report.get("source", name) for name, report in reports]
    if isinstance(sources, dict):
        source_names.extend(name for name in result.get("errors", {}) if name not in sources)
    lines.append(field("Sources", ", ".join(source_names)))
    partial = result.get("complete") is False or bool(result.get("errors")) or any(report.get("complete") is False or report.get("errors") for _, report in reports)
    noun = "vulnerability" if len(records) == 1 else "vulnerabilities"
    lines.append(field("Result", f"{'Partial' if partial else 'Complete'} | {len(records)} {noun}"))
    if result.get("pending_sources"):
        lines.append(field("Pending sources", ", ".join(result["pending_sources"])))
    if not records:
        lines.extend(["", "No vulnerabilities were retrieved" if partial else "No vulnerabilities found"])
    for index, (source, record) in enumerate(records, start=1):
        lines.extend(["", "-" * min(columns, 80), ""])
        for label, key in FIELDS:
            value = severity(record.get("cvss")) if key == "severity" else record.get(key)
            if isinstance(value, (list, tuple)):
                value = ", ".join(readable(item) for item in value) or None
            lines.append(field(label, value))
        lines.extend([field("Source", source), field("Link", record.get("link")), field("Vulnerability", f"{index}/{len(records)}")])
    diagnostics = []
    for name, report in reports:
        for error in report.get("errors", []):
            location = f"{readable(error['url'])} | " if error.get("url") else ""
            diagnostics.append(f"{report.get('source', name)}: {location}{readable(error.get('error'))}")
    if isinstance(result.get("errors"), dict):
        diagnostics.extend(f"{name}: {readable(error)}" for name, error in result["errors"].items())
    if diagnostics:
        lines.extend(["", "Errors:"] + [f"  {message}" for message in diagnostics])
    return "\n".join(lines)


def new_report_path(result):
    """Give each invocation a separate report in the project's ignored results directory."""
    def component(value):
        return re.sub(r"[^a-zA-Z0-9._-]", "_", str(value)).strip(".") or "unknown"

    kind = component(result.get("product_type", "target"))
    target = component(result.get("version") if kind == "core" else result.get("slug", "unknown"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    source = "combined" if "sources" in result else component(result.get("source", "source")).lower()
    directory = Path(__file__).resolve().parents[1] / "results" / kind / target
    if kind != "core" and result.get("version"):
        directory /= component(result["version"])
    return directory / f"{stamp}-{source}-{uuid4().hex}.txt"


def save_vulnerability_report(result, path=None):
    """Atomically replace a report only after the full UTF-8 text is on disk."""
    path = Path(path) if path is not None else new_report_path(result)
    combined = isinstance(result.get("sources"), dict)
    text = format_vulnerability_report(result, deduplicate=combined) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
    return path


def save_report_checkpoint(result, path):
    """Keep the previous report available if an update cannot be written."""
    try:
        save_vulnerability_report(result, path)
    except OSError as error:
        progress_log.failure(f"Could not save report to {path}: {error}")
        return False
    return True


def announce_saved_report(path):
    progress_log.success(f"Saved report: {path}")
    print(file=sys.stderr, flush=True)
