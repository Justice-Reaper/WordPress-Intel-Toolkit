"""Look up plugin, theme, or WordPress Core vulnerabilities on Wordfence."""

import math
import re
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urljoin, urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from common.scraper_common import progress_log, vulnerability_progress, listing_progress, validate_version_threshold, product_listing_ranges, listing_may_match, read_detail_or_skip, finish_detail_progress, core_listing_ranges, detail_progress, validate_vulnerability


BASE_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/"
PRODUCT_TYPES = {
    "plugin": "wordpress-plugins",
    "theme": "wordpress-themes",
    "core": "wordpress-core",
}
PAGE_LOAD_TIMEOUT = 15
CHALLENGE_TIMEOUT = 15
CORE_LISTING_URL = f"{BASE_URL}wordpress-core"


def parse_html_text(html):
    parts = []

    class TextCollector(HTMLParser):
        BLOCK_TAGS = {"br", "div", "li", "p", "section", "tr", "td", "th", "h1", "h2", "h3", "dt", "dd"}

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.ignored_depth = 0

        def handle_starttag(self, tag, attrs):
            if tag in {"script", "style", "svg", "noscript"}:
                self.ignored_depth += 1
            if tag in self.BLOCK_TAGS:
                parts.append("\n")

        def handle_endtag(self, tag):
            if tag in self.BLOCK_TAGS:
                parts.append("\n")
            if tag in {"script", "style", "svg", "noscript"} and self.ignored_depth:
                self.ignored_depth -= 1

        def handle_data(self, data):
            if not self.ignored_depth:
                parts.append(data)

    collector = TextCollector()
    collector.feed(html)
    return "\n".join(" ".join(line.split()) for line in "".join(parts).splitlines() if line.strip())


class PageHeadingParser(HTMLParser):
    """Read the detail heading, including pages using h2 or Open Graph metadata."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.headings = []
        self.active_tag = None
        self.parts = []
        self.meta_title = ""
        self.document_title = ""
        self.in_document_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and (attrs.get("property") or attrs.get("name") or "").casefold() == "og:title":
            self.meta_title = attrs.get("content", "")
        if tag == "title":
            self.in_document_title = True
        if tag in {"h1", "h2"} and self.active_tag is None:
            self.active_tag = tag
            self.parts = []

    def handle_data(self, data):
        if self.active_tag is not None:
            self.parts.append(data)
        if self.in_document_title:
            self.document_title += data

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_document_title = False
        if tag == self.active_tag:
            self.headings.append((tag, " ".join("".join(self.parts).split())))
            self.active_tag = None

    @property
    def title(self):
        for tag, value in self.headings:
            if tag == "h1" and value:
                return value
        for tag, value in self.headings:
            if tag == "h2" and re.search(r"(?:[<>]=?\s*)?\d+(?:\.\d+)+", value):
                return value
        metadata = self.meta_title or self.document_title
        if metadata:
            return re.sub(r"\s+(?:—|–|-|\|)\s+Wordfence(?: Intelligence)?.*$", "", " ".join(metadata.split()), flags=re.I)
        excluded = {"vulnerability details", "wordfence intelligence", "references", "description", "recent vulnerabilities", "related vulnerabilities"}
        return next((value for _tag, value in self.headings if value and value.casefold() not in excluded), "")


def load_vulnerability_page(page, url, expand_ranges=False, client=None, on_wait=None):
    def ready(html):
        return is_vulnerability_detail(html)
    html = load_rendered_page(page, url, ready, client=client, on_wait=on_wait)
    if expand_ranges:
        expand_version_ranges(page)
        html = page.content()
    return html


def expand_version_ranges(page):
    """Click disclosure controls so hidden affected/patched versions are rendered."""
    expand_pattern = re.compile(r"Expand to see \d+ more (?:affected version ranges|patched versions?)", re.IGNORECASE)
    for _ in range(20):
        controls = page.locator("button, a, [role='button']").filter(has_text=expand_pattern)
        if controls.count() == 0:
            return
        visible = [control for control in controls.all() if control.is_visible()]
        if not visible:
            return
        control = visible[0]
        try:
            control.click(timeout=3000)
            page.wait_for_timeout(150)
        except PlaywrightError as error:
            raise RuntimeError("Could not expand all Wordfence version ranges") from error
    remaining = page.locator("button, a, [role='button']").filter(has_text=expand_pattern)
    if any(control.is_visible() for control in remaining.all()):
        raise RuntimeError("Wordfence still has collapsed version ranges after 20 expansion attempts")


def extract_version_ranges(text, section_name="Affected"):
    """Read ranges only inside the requested labeled detail section."""
    start = re.compile(rf"^{re.escape(section_name)}\s+Versions?\s*[:|]?\s*(.*)$", re.I)
    boundary = re.compile(
        r"^(?:Affected Versions?|Patched Versions?|CVSS|CVE(?: ID)?|Software Type|"
        r"Software Slug|Patched\?|Publicly Published|Publicly Updated|Last Updated|"
        r"Researchers?|References|Recent vulnerabilities|Description|Disclosure Timeline|"
        r"Exploitability|Impact|CWE)(?=\s|:|$)", re.I,
    )
    version = re.compile(r"(?:[<>]=?\s*)?\d+(?:\.\d+){1,3}(?:\s*(?:-|–|to)\s*\d+(?:\.\d+){1,3})?", re.I)
    active = False
    ranges = []
    for line in text.splitlines():
        line = " ".join(line.split()).strip("| ")
        if not active:
            match = start.fullmatch(line)
            if not match:
                continue
            active = True
            candidate = match.group(1)
        else:
            if boundary.match(line):
                break
            candidate = line
        candidate = candidate.lstrip("•*- ")
        if version.fullmatch(candidate):
            ranges.append(candidate)
    return list(dict.fromkeys(ranges))


DETAIL_FIELD_LABELS = (
    "CVE", "CVE ID", "CVSS", "Publicly Published", "Publicly Updated", "Last Updated",
    "Software Type", "Software Slug", "Patched?", "Affected Version", "Affected Versions",
    "Patched Version", "Patched Versions", "Researchers", "Researcher", "Description",
)


def detail_field(text, label):
    """Read the first labeled value without borrowing from another section."""
    def valid_value(value):
        value = value.strip()
        if value.casefold() in {"unknown", "n/a", "not assigned", "pending", "reserved", "-"}:
            return True
        if label == "CVE":
            return bool(re.match(r"^CVE-\d{4}-\d+\b", value, re.I))
        if label == "CVSS":
            return bool(re.fullmatch(r"(?:10(?:\.0)?|[0-9](?:\.\d+)?)(?:\s*\([^)]*\))?", value))
        return True

    lines = text.splitlines()
    pattern = re.compile(rf"^{re.escape(label)}{'(?: ID)?' if label == 'CVE' else ''}\s*[:|]?\s*(.*)$", re.I)
    for index, line in enumerate(lines):
        if re.fullmatch(r"Recent vulnerabilities|Related vulnerabilities", line.strip(), re.I):
            break
        match = pattern.fullmatch(line.strip())
        if not match:
            continue
        if match.group(1).strip():
            value = match.group(1).strip()
            if valid_value(value):
                return value
            continue
        for value in lines[index + 1:]:
            value = value.strip()
            if not value:
                continue
            if value.rstrip(":| ").casefold() in {name.casefold() for name in DETAIL_FIELD_LABELS}:
                return ""
            if re.fullmatch(r"References|Recent vulnerabilities|Related vulnerabilities", value, re.I):
                return ""
            return value if valid_value(value) else ""
        return ""
    return ""


def is_vulnerability_detail(html):
    """Identify a detail page without requiring every optional metadata field."""
    text = parse_html_text(html)
    heading = PageHeadingParser()
    heading.feed(html)
    title = heading.title
    versioned_title = bool(re.search(r"[<>]=?\s*\d+(?:\.\d+)+|\d+(?:\.\d+)+\s*[-–]", title))
    primary = re.split(r"(?im)^\s*(?:Recent|Related) vulnerabilities(?:\s+in\s+[^\n]+)?\s*$", text, maxsplit=1)[0]
    metadata = any(detail_field(primary, label) for label in ("CVE", "CVSS", "Software Slug", "Software Type", "Affected Version", "Affected Versions"))
    marker = bool(re.search(r"Vulnerability Details", primary, re.I))
    generic = {"", "vulnerability details", "wordfence", "wordfence intelligence", "browser verification", "just a moment", "access denied"}
    meaningful_title = title.casefold().strip(" .") not in generic
    return bool(versioned_title or (marker and meaningful_title) or (metadata and (meaningful_title or marker)))


def parse_vulnerability_record(html):
    if not is_vulnerability_detail(html):
        raise RuntimeError("Wordfence returned an unexpected detail page or browser verification")
    text = parse_html_text(html)
    primary_text = re.split(r"(?im)^\s*(?:Recent|Related) vulnerabilities(?:\s+in\s+[^\n]+)?\s*$", text, maxsplit=1)[0]
    heading = PageHeadingParser()
    heading.feed(html)
    cve_match = re.search(r"\bCVE-\d{4}-\d+\b", detail_field(primary_text, "CVE"), re.I)
    status_match = re.search(r"\b(Yes|No)\b", detail_field(primary_text, "Patched?"), re.I)
    slug = detail_field(primary_text, "Software Slug")
    software_type = detail_field(primary_text, "Software Type")
    if not slug and software_type.casefold() in {"core", "wordpress", "wordpress core"}:
        slug = "wordpress"
    return validate_vulnerability({
        "title": heading.title,
        "cve_id": cve_match.group(0) if cve_match else "Unknown",
        "cvss": detail_field(primary_text, "CVSS"),
        "date": detail_field(primary_text, "Publicly Published"),
        "status": ("Patched" if status_match.group(1).casefold() == "yes" else "Unpatched") if status_match else "Unknown",
        "software_type": software_type,
        "software_slug": slug.split()[0].split("(")[0] if slug else "",
        "affected_versions": extract_version_ranges(primary_text, "Affected") or core_listing_ranges(heading.title, "wordfence") or product_listing_ranges(heading.title, "wordfence"),
        "patched_versions": extract_version_ranges(primary_text, "Patched"),
    })


class DetailLinksParser(HTMLParser):
    """Read only detail links and pagination from a Wordfence listing."""

    def __init__(self, listing_url):
        super().__init__(convert_charrefs=True)
        self.listing_url = listing_url
        self.path = urlparse(listing_url).path.rstrip("/")
        self.links = set()
        self.last_page = 1
        self.table_depth = 0
        self.card_depth = 0
        self.titles = {}
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "table":
            self.table_depth += 1
        if tag == "div":
            if self.card_depth:
                self.card_depth += 1
            elif "threat-intel-vulns-card" in attrs.get("class", "").split():
                self.card_depth = 1
        href = attrs.get("href", "")
        if tag != "a" or not href:
            return
        url = urljoin(self.listing_url, href)
        parsed = urlparse(url)
        if parsed.netloc != "www.wordfence.com":
            return
        if parsed.path.startswith(self.path + "/"):
            suffix = parsed.path[len(self.path) + 1:].strip("/")
            auxiliary = {"submit", "report", "edit", "submit-vulnerability", "report-vulnerability"}
            if (self.table_depth or self.card_depth) and suffix and "/" not in suffix and suffix.casefold() not in auxiliary:
                detail_url = parsed._replace(fragment="").geturl()
                self.links.add(detail_url)
                self.anchor = {"url": detail_url, "text": []}
        elif parsed.path.rstrip("/") == self.path:
            for value in parse_qs(parsed.query).get("page", []):
                if value.isdigit():
                    self.last_page = max(self.last_page, int(value))


    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            title = " ".join(" ".join(self.anchor["text"]).split())
            url = self.anchor["url"]
            if len(title) > len(self.titles.get(url, "")):
                self.titles[url] = title
            self.anchor = None
        if tag == "table" and self.table_depth:
            self.table_depth -= 1
        if tag == "div" and self.card_depth:
            self.card_depth -= 1


def load_rendered_page(page, url, ready, client=None, on_wait=None):
    """Wait for rendered content and respect the configured browser retry budget."""
    attempt = 0
    navigation_timeout = getattr(client, "page_load_timeout", PAGE_LOAD_TIMEOUT)
    wait_timeout = getattr(client, "browser_wait_timeout", CHALLENGE_TIMEOUT)
    while True:
        try:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=navigation_timeout * 1000)
            except PlaywrightTimeoutError:
                pass
            started = time.monotonic()
            deadline = started + wait_timeout
            last_notice = -1
            while time.monotonic() < deadline:
                try:
                    html = page.content()
                except PlaywrightError as error:
                    if "navigat" not in str(error).casefold():
                        raise
                    page.wait_for_timeout(500)
                    continue
                if ready(html):
                    return html
                elapsed = int(time.monotonic() - started)
                if on_wait is not None and elapsed // 5 != last_notice:
                    last_notice = elapsed // 5
                    on_wait(f"Waiting for page content or browser verification | {elapsed}/{wait_timeout:g}s")
                page.wait_for_timeout(500)
            raise RuntimeError(f"Wordfence did not render the expected content for {url} within {wait_timeout:g} seconds")
        except (RuntimeError, PlaywrightError) as error:
            if client is None or (client.max_retries is not None and attempt >= client.max_retries):
                raise RuntimeError(f"Could not load Wordfence page {url}: {error}") from error
            attempt += 1
            progress_log.warning(f"Wordfence page failed; retry {attempt} in {client.retry_delay:g} seconds")
            time.sleep(client.retry_delay)


def lookup(product_type, target, client=None, version=None):
    if product_type not in PRODUCT_TYPES:
        raise ValueError("Type must be plugin, theme, or core")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", target):
        raise ValueError("The target must be a valid product slug or numeric Core version")
    if product_type == "core" and not re.fullmatch(r"\d+(?:\.\d+){1,3}", target):
        raise ValueError("Core version must be numeric, for example 6.8.5")
    threshold = validate_version_threshold(target if product_type == "core" else version)
    listing_url = BASE_URL + PRODUCT_TYPES[product_type]
    if product_type != "core":
        listing_url += "/" + quote(target, safe="-_.")
    delay = client.delay if client is not None else 1.0
    links = set()
    listing_titles = {}
    listing_pages = {}
    vulnerabilities = []
    errors = []
    with vulnerability_progress() as status:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=not getattr(client, "show_browser", False))
                try:
                    page = browser.new_page(locale="en-US", viewport={"width": 1440, "height": 1200})
                    number, last_page = 1, 1
                    while number <= last_page:
                        url = f"{listing_url}?sortby=date&sort=desc&page={number}" if product_type == "core" else listing_url
                        def ready(html):
                            parser = DetailLinksParser(listing_url)
                            parser.feed(html)
                            return bool(parser.links) or bool(re.search(r"(?m)^\s*(?:0 vulnerabilities?|no vulnerabilities (?:found|reported))\s*$", parse_html_text(html), re.I))
                        status.status(listing_progress(number, count=len(links)))
                        html = load_rendered_page(page, url, ready, client=client, on_wait=lambda _message: status.status(listing_progress(number, count=len(links))))
                        parser = DetailLinksParser(listing_url)
                        parser.feed(html)
                        for detail_url in parser.links:
                            title = parser.titles.get(detail_url, "")
                            if not listing_may_match({"listing_text": title}, threshold, "wordfence", product_type):
                                continue
                            links.add(detail_url)
                            listing_pages.setdefault(detail_url, number)
                            if len(title) > len(listing_titles.get(detail_url, "")):
                                listing_titles[detail_url] = title
                        if product_type == "core":
                            last_page = max(last_page, parser.last_page)
                            total = re.search(r"Showing\s+([\d,]+)\s*[-–]\s*([\d,]+)\s+of\s+([\d,]+)", parse_html_text(html), re.I)
                            if total:
                                first, last, count = [int(v.replace(",", "")) for v in total.groups()]
                                if number == 1 and last >= first:
                                    last_page = max(last_page, math.ceil(count / (last - first + 1)))
                        status.status(listing_progress(number, count=len(links)))
                        number += 1
                        if delay:
                            time.sleep(delay)
                    candidates = [{"url": url, "listing_text": listing_titles[url]}
                                  for url in sorted(links, key=lambda item: (listing_pages[item], item))]
                    for index, listed in enumerate(candidates, start=1):
                        url = listed["url"]
                        status.status(detail_progress(index, len(candidates)))
                        def read_record():
                            html = load_vulnerability_page(page, url, expand_ranges=True, client=client, on_wait=lambda _message: status.status(detail_progress(index, len(candidates))))
                            return parse_vulnerability_record(html)
                        record = read_detail_or_skip(read_record, index, len(candidates), url, status, errors, extra_errors=(PlaywrightError,))
                        if record is None:
                            continue
                        vulnerabilities.append(record)
                        status.status(detail_progress(index, len(candidates)))
                        if delay:
                            time.sleep(delay)
                finally:
                    browser.close()
        except PlaywrightError as error:
            raise RuntimeError(f"Could not load Wordfence in bundled Chromium: {error}") from error
        finish_detail_progress(status, len(candidates), errors)
    result = {"source": "Wordfence", "product_type": product_type, "version": threshold, "url": listing_url, "vulnerabilities": vulnerabilities, "errors": errors, "complete": not errors}
    if product_type != "core":
        result["slug"] = target
    if product_type == "core":
        result["pages_scanned"] = last_page
    return result
