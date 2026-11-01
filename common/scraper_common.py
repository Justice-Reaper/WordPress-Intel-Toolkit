"""Shared CLI, HTTP, persistence, and parsing helpers for the WordPress tools."""

import argparse
import math
import os
import tempfile
import re
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from http.client import IncompleteRead
from urllib.request import Request, urlopen
from urllib.parse import urlparse, unquote
from pwnlib import term
from pwnlib.term import text
from pwnlib.context import context
from pwnlib.log import getLogger, install_default_handler


context.log_console = sys.stderr
install_default_handler()
term.init()
text.when = "auto"
progress_log = getLogger("pwnlib.wordpress.slug-dictionaries")


def handle_sigint(_signal_number, _frame):
    print("\n\n[!] Exiting ...\n", file=sys.stderr, flush=True)
    sys.exit(1)


def run_cli(entrypoint):
    """Handle Ctrl+C once at the command boundary, after resources are cleaned up."""
    try:
        return entrypoint()
    except KeyboardInterrupt:
        handle_sigint(None, None)


def progress(message, rate=5):
    """Create a pwntools indicator with the requested update interval."""
    return progress_log.progress(message, rate=rate)


def dictionary_progress(kind, page, count, total=None):
    """Format the product type, current page, and collected slug count."""
    message = f"{kind.removesuffix('s').title()} | Page {page} | {count} slugs"
    return f"{message} of {total}" if total is not None else message


def non_negative_float(value):
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Must be a non-negative number") from error
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("Must be a non-negative number")
    return number


def positive_float(value):
    number = non_negative_float(value)
    if number == 0:
        raise argparse.ArgumentTypeError("Must be greater than zero")
    return number


def non_negative_int(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Must be a non-negative integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("Must be a non-negative integer")
    return number


class CommandHelpFormatter(argparse.HelpFormatter):
    """Keep option descriptions aligned with a generous fixed gap."""

    def __init__(self, prog):
        super().__init__(prog, width=180, max_help_position=48)
        self._action_max_length = 44


def argument_parser():
    """Build the same compact English help layout for every executable command."""
    specification = getattr(sys.modules.get("__main__"), "__spec__", None)
    command = f"python -m {specification.name}" if specification else None
    parser = argparse.ArgumentParser(
        prog=command,
        usage="%(prog)s [options]",
        formatter_class=CommandHelpFormatter,
    )
    parser._positionals.title = "Target"
    parser._optionals.title = "General options"
    return parser


def add_request_arguments(parser, http=True):
    settings = parser.add_argument_group("Request settings")
    settings.add_argument("--timeout-between-requests", type=non_negative_float, default=1.0, metavar="SECONDS",
                          help="Pause between successful requests or page loads (default: 1 second)")
    settings.add_argument("--timeout-beetwen-requests", dest="timeout_between_requests", type=non_negative_float,
                          default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    if http:
        settings.add_argument("--request-timeout", type=positive_float, default=30, metavar="SECONDS",
                              help="HTTP connection/read timeout (default: 30 seconds; HTTP sources only)")
    settings.add_argument("--retry-delay-on-non-200", type=non_negative_float, default=30.0, metavar="SECONDS",
                          help="Pause before retrying a failed load (default: 30 seconds; 0 disables the pause)")
    retries = settings.add_mutually_exclusive_group()
    retries.add_argument("--max-retries-on-non-200", type=non_negative_int, default=3, metavar="COUNT",
                        help="Retries after the first attempt (default: 3; 0 disables retries)")
    retries.add_argument("--infinite-retries-on-non-200", action="store_true",
                        help="Retry without a limit (default: disabled)")


def add_browser_arguments(parser, patchstack_core=False, patchstack_dictionaries=False):
    settings = parser.add_argument_group("Browser settings")
    scope = ("Wordfence and Patchstack dictionaries" if patchstack_dictionaries
             else "Wordfence and Patchstack Core" if patchstack_core else "Wordfence")
    settings.add_argument("--show-browser", action="store_true",
                          help=f"Open a visible Chromium window (default: headless; {scope})")
    settings.add_argument("--page-load-timeout", type=positive_float, default=15, metavar="SECONDS",
                          help="Maximum navigation time per attempt (default: 15 seconds)")
    settings.add_argument("--browser-wait-timeout", type=positive_float, default=15, metavar="SECONDS",
                          help="Maximum wait for page HTML per attempt (default: 15 seconds)")


def vulnerability_progress():
    """Show discovery first, then classification of the selected links."""
    return progress_log.progress("", status="Page 1 | Vulnerabilities found: 0", rate=0.1)


def listing_progress(page, total=None, count=0):
    return f"Page {page} | Vulnerabilities found: {count}"


def detail_progress(index, total):
    return f"Classifying vulnerability: {index}/{total}"


def read_detail_or_skip(loader, index, total, url, status, errors, extra_errors=()):
    """Record failures for the final report and continue with the next detail."""
    expected_errors = (RuntimeError, ValueError, OSError) + extra_errors
    try:
        record = loader()
        record["link"] = url
        return record
    except expected_errors as error:
        errors.append({"url": url, "error": str(error)})
        return None


def finish_detail_progress(status, total, errors):
    message = f"Finished | Vulnerabilities found: {total} | Failed/skipped: {len(errors)}"
    (status.failure if errors else status.success)(message)


class HttpClient:
    def __init__(self, delay=1.0, retry_delay=30.0, max_retries=3, log_path=None, timeout=30):
        self.delay = delay
        self.retry_delay = retry_delay
        self.max_retries = max_retries
        self.log_path = log_path
        self.timeout = timeout
        self.last_request_succeeded = False

    def get(self, url, headers=None):
        if self.last_request_succeeded and self.delay:
            time.sleep(self.delay)
        self.last_request_succeeded = False
        attempt = 0
        while True:
            request = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; WordPressSlugDictionary/1.0)",
                "Accept": "*/*",
                **(headers or {}),
            })
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    if response.status == 200:
                        body = response.read()
                        self.last_request_succeeded = True
                        return body
                    status = response.status
            except HTTPError as error:
                status = error.code
                error.close()
            except (URLError, TimeoutError, ConnectionError, IncompleteRead) as error:
                status = getattr(getattr(error, "reason", None), "errno", "network-error")

            if self.log_path:
                stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                with self.log_path.open("a", encoding="utf-8") as log:
                    log.write(f"{stamp} error={status} attempt={attempt + 1} url={url}\n")
            if self.max_retries is not None and attempt >= self.max_retries:
                raise RuntimeError(f"HTTP/network error ({status}) for {url}; exhausted {self.max_retries} retries")
            progress_log.warning(f"HTTP/network error ({status}) for {url}; retrying in {self.retry_delay} seconds")
            attempt += 1
            time.sleep(self.retry_delay)


def client_from_args(args, log_path):
    retries = None if args.infinite_retries_on_non_200 else args.max_retries_on_non_200
    client = HttpClient(args.timeout_between_requests, args.retry_delay_on_non_200, retries, log_path, timeout=getattr(args, "request_timeout", 30))
    client.show_browser = getattr(args, "show_browser", False)
    client.browser_wait_timeout = getattr(args, "browser_wait_timeout", 15)
    client.page_load_timeout = getattr(args, "page_load_timeout", 15)
    return client


def save_slugs(path, slugs, *, preserve_order=False):
    """Write unique slugs atomically, preserving input order when requested."""
    values = {}
    for slug in slugs:
        if not isinstance(slug, str):
            raise ValueError("A dictionary slug must be a string")
        value = slug.strip().casefold()
        if not value:
            continue
        if value in {".", ".."} or any(char.isspace() or char in "/\\" for char in value):
            raise ValueError(f"Invalid dictionary slug: {slug!r}")
        values.setdefault(value, None)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            for value in (values if preserve_order else sorted(values)):
                stream.write(value + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    progress_log.success(f"Saved {len(values)} slugs to {path}")


VERSION_TOKEN = r"\d+(?:\.\d+){1,3}"
VERSION_EXPRESSION = re.compile(
    rf"(?:<=|>=|<|>)\s*{VERSION_TOKEN}|{VERSION_TOKEN}\s*(?:-|–|to)\s*{VERSION_TOKEN}|{VERSION_TOKEN}",
    re.IGNORECASE,
)


def version_expressions(value):
    """Extract independent version expressions without losing range boundaries."""
    return list(dict.fromkeys(match.group(0).strip() for match in VERSION_EXPRESSION.finditer(value)))


def ranges_reach_threshold(expressions, target):
    """Return whether any affected range reaches the target or a later version."""
    def numeric(value):
        parts = tuple(map(int, value.split(".")))
        return parts + (0,) * (4 - len(parts))
    threshold = numeric(target)
    for expression in expressions:
        expression = expression.strip()
        comparison = re.fullmatch(rf"([<>]=?)\s*({VERSION_TOKEN})", expression)
        if comparison:
            operator, bound = comparison.groups()
            if operator in {">", ">="} or (numeric(bound) > threshold if operator == "<" else numeric(bound) >= threshold):
                return True
            continue
        interval = re.fullmatch(rf"({VERSION_TOKEN})\s*(?:-|–|to)\s*({VERSION_TOKEN})", expression, re.I)
        if interval:
            if numeric(interval.group(1)) <= numeric(interval.group(2)) and numeric(interval.group(2)) >= threshold:
                return True
        elif re.fullmatch(VERSION_TOKEN, expression) and numeric(expression) >= threshold:
            return True
    return False


def core_listing_ranges(text, source):
    """Read only an unambiguous affected range from a Core listing record."""
    text = " ".join(text.replace("≤", "<=").replace("≥", ">=").split())
    token = VERSION_TOKEN + r"(?![\d.])"
    expression = rf"(?:[<>]=?\s*{token}|{token}\s*(?:-|–|to)\s*{token}|{token})"
    if source in {"wordfence", "wpscan"}:
        match = re.match(rf"^(?:WordPress(?: Core)?|WP)\s+({expression})(?:\s*[-–:]\s*|$)", text, re.I)
        return [match.group(1)] if match else []
    if source == "patchstack":
        match = re.search(rf"([<>]=?\s*{token}|{token}\s*(?:-|–|to)\s*{token})", text, re.I)
        if not match:
            match = re.search(rf"WordPress(?: Core)?\s+({token})(?:\s|$)", text, re.I)
        return [match.group(1)] if match else []
    return []


def validate_version_threshold(value):
    """Validate the numeric threshold accepted by every software type."""
    if not isinstance(value, str) or not re.fullmatch(VERSION_TOKEN, value):
        raise ValueError("Version must contain two to four numeric components, for example 4.17.0")
    return value


def product_listing_ranges(text, source):
    """Recognize product listing ranges without treating product-name numbers as versions."""
    text = " ".join(text.replace("≤", "<=").replace("≥", ">=").split())
    token = VERSION_TOKEN + r"(?![\w.])"
    expression = rf"(?:[<>]=?\s*{token}|{token}\s*(?:-|–|to)\s*{token}|{token})"
    if source in {"wordfence", "wpscan"}:
        match = re.match(rf"^.+?\s+({expression}(?:\s*(?:,|;|and|&|/)\s*{expression})*)\s+[-–:]\s+\S", text, re.I)
        return version_expressions(match.group(1)) if match else []
    if source == "patchstack":
        return list(dict.fromkeys(match.group(0).strip() for match in re.finditer(
            rf"(?<![\w.])(?:[<>]=?\s*{token}|{token}\s*(?:-|–|to)\s*{token})", text, re.I,
        )))
    return []


def listing_may_match(record, target, source, product_type):
    ranges = (core_listing_ranges(record.get("listing_text", ""), source) if product_type == "core"
              else product_listing_ranges(record.get("listing_text", ""), source))
    return bool(ranges) and ranges_reach_threshold(ranges, target)


def validate_vulnerability(record):
    """Reject an unexpected page instead of emitting an empty vulnerability record."""
    meaningful = any(value for value in record.values() if not isinstance(value, str)) or any(value.strip().casefold() not in {"", "unknown", "n/a"} for value in record.values() if isinstance(value, str))
    if not meaningful:
        raise RuntimeError("The page contains no readable vulnerability fields")
    score = re.search(r"(?<![\d.])(?:10(?:\.0)?|[0-9](?:\.\d+)?)(?![\d.])", record["cvss"])
    record["cvss"] = score.group(0) if score else ""
    if record["software_type"].casefold() in {"wordpress", "wordpress core", "core"}:
        record["software_type"] = "Core"
    return record
