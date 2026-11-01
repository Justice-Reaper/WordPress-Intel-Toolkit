"""Look up plugin, theme, or WordPress Core vulnerabilities on Patchstack."""

import re
import time
from contextlib import nullcontext
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urljoin, urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from common.scraper_common import progress_log, vulnerability_progress, listing_progress, validate_version_threshold, product_listing_ranges, listing_may_match, read_detail_or_skip, finish_detail_progress, core_listing_ranges, detail_progress, validate_vulnerability


BASE_URL = "https://patchstack.com"
GLOBAL_LISTING_URLS = {kind: f"{BASE_URL}/database?platform=wordpress&type={kind}&page=1"
                       for kind in ("plugin", "theme", "core")}
CORE_LISTING_URL = GLOBAL_LISTING_URLS["core"]
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
}


def clean(value):
    return " ".join(value.split())


class ProductPageParser(HTMLParser):
    """Find vulnerability detail links on a Patchstack product page."""

    def __init__(self, expected_path):
        super().__init__(convert_charrefs=True)
        self.expected_path = expected_path.rstrip("/") + "/vulnerability/"
        self.records = []
        self.anchor = None

    def is_detail_path(self, path):
        return path.startswith(self.expected_path)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self.anchor is not None and tag in {"div", "span", "br", "td", "th", "p"}:
            self.anchor["text"].append("\n")
        href = attrs.get("href", "")
        listing_url = BASE_URL + self.expected_path.split("/vulnerability/")[0] + "/vulnerabilities"
        absolute = urljoin(listing_url, href)
        if urlparse(absolute).netloc != "patchstack.com":
            return
        path = urlparse(absolute).path
        if tag == "a" and self.is_detail_path(path):
            self.anchor = {"url": urlparse(absolute)._replace(fragment="").geturl(), "text": []}

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["text"].append(data)

    def handle_endtag(self, tag):
        if self.anchor is not None and tag in {"div", "span", "td", "th", "p"}:
            self.anchor["text"].append("\n")
        if tag == "a" and self.anchor is not None:
            self.records.append({"url": self.anchor["url"], "listing_text": " ".join(" ".join(self.anchor["text"]).split())})
            self.anchor = None


class GlobalPageParser(ProductPageParser):
    """Read detail links only for the requested WordPress category."""

    def __init__(self, kind):
        self.product_type = "wordpress" if kind == "core" else kind
        super().__init__(f"/database/wordpress/{self.product_type}")

    def is_detail_path(self, path):
        return bool(re.fullmatch(rf"/database/wordpress/{self.product_type}/[^/]+/vulnerability/[^/]+/?", path))


def read_global_listing_page(page, client, kind, pagination, page_number):
    """Navigate or advance Load more, respecting browser timeout/retry settings."""
    attempt = 0
    navigation_timeout = getattr(client, "page_load_timeout", 15) * 1000
    content_timeout = getattr(client, "browser_wait_timeout", 15)

    def snapshot():
        parser = GlobalPageParser(kind)
        parser.feed(page.content())
        parser.close()
        urls = {record["url"] for record in parser.records}
        return parser, urls

    def ready(urls):
        if pagination.get("current_page") != page_number:
            return False
        if pagination.get("count") == 0 and pagination.get("next_page_url") is None:
            return True
        expected_urls = pagination.get("_page_urls", set())
        return bool(expected_urls and expected_urls.issubset(urls))

    while True:
        try:
            if page_number == 1:
                try:
                    page.goto(GLOBAL_LISTING_URLS[kind], wait_until="domcontentloaded", timeout=navigation_timeout)
                except PlaywrightTimeoutError:
                    pass
            else:
                parser, urls = snapshot()
                if ready(urls):
                    return parser
                consent = page.get_by_role("button", name="Reject All", exact=True).first
                if consent.count() and consent.is_visible():
                    consent.click(timeout=navigation_timeout)
                page.get_by_role("button", name="Load more", exact=True).click(timeout=navigation_timeout)
            deadline = time.monotonic() + content_timeout
            while time.monotonic() < deadline:
                parser, urls = snapshot()
                if ready(urls):
                    return parser
                page.wait_for_timeout(250)
            raise RuntimeError(f"Patchstack did not render {kind} listing page {page_number} within {content_timeout:g} seconds")
        except (RuntimeError, PlaywrightError) as error:
            if client.max_retries is not None and attempt >= client.max_retries:
                raise RuntimeError(f"Could not load Patchstack {kind} listing: {error}") from error
            attempt += 1
            progress_log.warning(f"Patchstack {kind} page failed; retry {attempt} in {client.retry_delay:g} seconds")
            time.sleep(client.retry_delay)


def iter_global_listing_pages(client, kind, on_page=None):
    """Follow the website's pages until its filtered next_page_url is null."""
    if kind not in GLOBAL_LISTING_URLS:
        raise ValueError("Patchstack listing type must be plugin, theme, or core")
    pagination = {}

    def capture_pagination(response):
        parsed = urlparse(response.url)
        query = parse_qs(parsed.query)
        if (parsed.netloc != "vdp.patchstack.com" or parsed.path != "/api/database/home"
                or query.get("platform") != ["wordpress"] or query.get("type") != [kind]):
            return
        try:
            payload = response.json()
        except (ValueError, PlaywrightError):
            return
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        metadata = vulnerabilities.get("pagination") if isinstance(vulnerabilities, dict) else None
        if isinstance(metadata, dict) and "next_page_url" in metadata:
            page_urls = set()
            segment = "wordpress" if kind == "core" else kind
            for record in vulnerabilities.get("data", []):
                if not isinstance(record, dict):
                    continue
                product = record.get("product_slug")
                issue = record.get("slug")
                if isinstance(product, str) and product and isinstance(issue, str) and issue:
                    page_urls.add(f"{BASE_URL}/database/wordpress/{segment}/{quote(product, safe='')}/vulnerability/{quote(issue, safe='')}")
            pagination.clear()
            pagination.update(metadata)
            pagination["_page_urls"] = page_urls

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not getattr(client, "show_browser", False))
            try:
                page = browser.new_page(locale="en-US", viewport={"width": 1440, "height": 1200})
                page.on("response", capture_pagination)
                number = 1
                while True:
                    if on_page is not None:
                        on_page(number)
                    parser = read_global_listing_page(page, client, kind, pagination=pagination, page_number=number)
                    next_url = pagination["next_page_url"]
                    if next_url is not None and (not isinstance(next_url, str) or not next_url.strip()):
                        raise RuntimeError("Patchstack returned an invalid next-page value")
                    rows = {}
                    for record in parser.records:
                        if len(record["listing_text"]) > len(rows.get(record["url"], {}).get("listing_text", "")):
                            rows[record["url"]] = record
                    yield number, list(rows.values())
                    if next_url is None:
                        break
                    more = page.get_by_role("button", name="Load more", exact=True)
                    if not more.count() or not more.is_visible():
                        raise RuntimeError(f"Patchstack omitted Load more before the final {kind} page")
                    number += 1
                    if client.delay:
                        time.sleep(client.delay)
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"Could not load Patchstack {kind} in bundled Chromium: {error}") from error


def core_listing_links(client, status=None, version=None):
    """Retain matching Core links while visiting every global listing page."""
    links = {}
    number = 0
    with (nullcontext(status) if status is not None else vulnerability_progress()) as status:
        pages = iter_global_listing_pages(client, "core", on_page=lambda n: status.status(listing_progress(n, count=len(links))))
        try:
            for number, rows in pages:
                for record in rows:
                    if version is not None and not listing_may_match(record, version, "patchstack", "core"):
                        continue
                    record["listing_page"] = number
                    links.setdefault(record["url"], record)
                status.status(listing_progress(number, count=len(links)))
        finally:
            pages.close()
        for record in links.values():
            record["listing_pages"] = number
    return list(links.values())


class DetailPageParser(HTMLParser):
    """Read Patchstack's labeled detail fields and vulnerability heading."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.label_depth = None
        self.value_depth = None
        self.fields = {}
        self.software_slug = ""
        self.slug_priority = 0
        self.title = ""
        self.active_key = None
        self.active_data = []
        self.capture_heading = False
        self.heading_data = []
        self.cve_data = []
        self.in_cve = False
        self.capture_value = False
        self.capture_label = False
        self.label_data = []

    def handle_starttag(self, tag, attrs):
        if tag not in {"br", "img", "hr", "input", "meta", "link", "source", "wbr"}:
            self.depth += 1
        if self.active_key and tag in {"br", "span", "div", "li"}:
            self.active_data.append(" ")
        attrs = dict(attrs)
        product = re.fullmatch(r"/database/wordpress/(?:plugin|theme|wordpress)/([^/]+)/vulnerabilities/?", urlparse(attrs.get("href", "")).path)
        priority = 2 if self.active_key == "_software_name" else 1
        if product and priority > self.slug_priority:
            self.software_slug = product.group(1)
            self.slug_priority = priority
        if tag == "link" and "canonical" in attrs.get("rel", "").casefold().split():
            canonical = re.fullmatch(r"/database/wordpress/(?:plugin|theme|wordpress)/([^/]+)/vulnerability/[^/]+/?", urlparse(attrs.get("href", "")).path)
            if canonical:
                self.software_slug = canonical.group(1)
                self.slug_priority = 3
        test_id = attrs.get("data-testid", "")
        if test_id == "title":
            self.label_depth = self.depth
            self.capture_label = True
            self.label_data = []
        elif test_id in ("value", "value-link"):
            self.active_key = getattr(self, "pending_key", None)
            self.pending_key = None
            self.active_data = []
            self.value_depth = self.depth
            self.capture_value = bool(self.active_key)
        if tag == "h1" and not self.title:
            self.capture_heading = True
            self.heading_data = []
        if test_id == "value-link":
            self.in_cve = True

    def handle_endtag(self, tag):
        if self.active_key and tag in {"span", "div", "li"}:
            self.active_data.append(" ")
        if self.capture_label and self.depth == self.label_depth:
            label = clean("".join(self.label_data)).casefold().rstrip(":")
            mapping = {
                "vulnerable versions": "affected_versions",
                "patched in": "patched_in",
                "cve id": "cve_id",
                "cvss severity": "cvss",
                "type": "software_type",
                "software": "_software_name",
                "published": "published",
            }
            self.pending_key = mapping.get(label)
            self.capture_label = False
        if self.in_cve and tag == "a":
            value = clean("".join(self.cve_data))
            if re.fullmatch(r"CVE-\d{4}-\d+", value, re.I):
                self.fields.setdefault("cve_id", value)
            self.in_cve = False
            self.cve_data = []
        if tag == "h1" and self.capture_heading:
            value = clean("".join(self.heading_data))
            if value and not self.title:
                self.title = value
            self.capture_heading = False
        if self.capture_value and self.depth == self.value_depth:
            value = clean("".join(self.active_data))
            if value:
                self.fields.setdefault(self.active_key, value)
            self.active_key = None
            self.active_data = []
            self.capture_value = False
        if tag not in {"br", "img", "hr", "input", "meta", "link", "source", "wbr"}:
            self.depth = max(0, self.depth - 1)

    def handle_data(self, data):
        if self.capture_label:
            self.label_data.append(data)
        if self.active_key:
            self.active_data.append(data)
        if self.capture_heading:
            self.heading_data.append(data)
        if self.in_cve:
            self.cve_data.append(data)


class VisibleTextParser(HTMLParser):
    """Collect readable page text with line breaks between block elements."""

    BLOCK_TAGS = {
        "article", "br", "dd", "div", "dt", "h1", "h2", "h3", "h4", "li",
        "p", "section", "span", "td", "th", "tr",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, _attrs):
        if tag in {"script", "style", "svg", "noscript"}:
            self.ignored_depth += 1
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag in {"script", "style", "svg", "noscript"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if not self.ignored_depth:
            self.parts.append(data)

    def text(self):
        return [clean(line) for line in "".join(self.parts).splitlines() if clean(line)]


DETAIL_LABELS = (
    "type", "vulnerable versions", "patched in", "cve id", "cvss severity",
    "credits", "published", "software", "owasp top 10", "classification",
    "required privilege", "developer", "psid", "references", "patchstack priority",
)


def visible_field(lines, label):
    """Read a field value from Patchstack's label/value text layout."""
    wanted = label.casefold().rstrip(":")
    for index, line in enumerate(lines):
        normalized = line.casefold().rstrip(":")
        if normalized == wanted:
            values = []
            for value_line in lines[index + 1:]:
                if value_line.casefold().rstrip(":") in DETAIL_LABELS:
                    break
                values.append(value_line)
            return " ".join(values).strip()
        if normalized.startswith(wanted + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def version_values(value):
    pattern = re.compile(
        r"(?:<=|<|>=|>)\s*\d+(?:\.\d+){1,3}|"
        r"\d+(?:\.\d+){1,3}\s*[-–]\s*\d+(?:\.\d+){1,3}|"
        r"\d+(?:\.\d+){1,3}"
    )
    return list(dict.fromkeys(match.group(0).strip() for match in pattern.finditer(value)))


def parse_detail(html, url):
    parser = DetailPageParser()
    parser.feed(html)
    parser.close()
    text_parser = VisibleTextParser()
    text_parser.feed(html)
    text_parser.close()
    lines = text_parser.text()
    if not any(re.match(r"^Vulnerable versions\b", line, re.I) for line in lines) and not parser.fields and parser.slug_priority < 3 and not version_values(parser.title):
        raise RuntimeError("Patchstack returned a page without vulnerability version details")

    fields = dict(parser.fields)
    label_pairs = {
        "affected_versions": "vulnerable versions",
        "patched_in": "patched in",
        "cve_id": "cve id",
        "cvss": "cvss severity",
        "published": "published",
        "software_type": "type",
    }
    for output_key, label in label_pairs.items():
        fields.setdefault(output_key, visible_field(lines, label))

    cve_match = re.search(r"\bCVE-\d{4}-\d+\b", fields.get("cve_id", ""), re.IGNORECASE)
    cvss = fields.get("cvss", "")
    score_number = re.search(r"\d+(?:\.\d+)?", cvss)
    if not score_number:
        for line in lines:
            score_match = re.fullmatch(r"CVSS(?: score)?\s+(\d+(?:\.\d+)?)", line, re.I)
            if score_match:
                cvss = score_match.group(1)
                score_number = re.search(r"\d+(?:\.\d+)?", cvss)
                break

    affected = fields.get("affected_versions", "")
    patched = fields.get("patched_in", "")
    if not affected:
        affected = visible_field(lines, "vulnerable versions")
    if not patched:
        patched = visible_field(lines, "patched in")
    affected_versions = version_values(affected) or core_listing_ranges(parser.title, "wordfence") or product_listing_ranges(parser.title, "wordfence")
    patched_versions = version_values(patched)
    software_slug = parser.software_slug
    return validate_vulnerability({
        "title": parser.title,
        "cve_id": cve_match.group(0) if cve_match else (fields.get("cve_id") or "Unknown"),
        "cvss": score_number.group(0) if score_number else cvss,
        "date": fields.get("published", ""),
        "status": "Patched" if patched_versions else ("Unpatched" if re.search(r"no fix|no patched version|no official fix|not fixed|unfixed|unpatched", patched, re.I) else "Unknown"),
        "software_type": fields.get("software_type", ""),
        "software_slug": software_slug,
        "affected_versions": affected_versions,
        "patched_versions": patched_versions,
    })


def listing_links(client, product_path, status=None, version=None, kind="core"):
    """Paginate the global Core category, or read one complete product listing."""
    if kind == "core":
        return core_listing_links(client, status=status, version=version)
    url = f"{BASE_URL}{product_path}/vulnerabilities"
    links = {}
    with (nullcontext(status) if status is not None else vulnerability_progress()) as status:
        status.status(listing_progress(1, count=0))
        html = client.get(url, REQUEST_HEADERS).decode("utf-8", errors="replace")
        parser = ProductPageParser(product_path)
        parser.feed(html)
        parser.close()
        if not parser.records and "vulnerability history" not in html.casefold():
            raise RuntimeError(f"Patchstack returned an unexpected listing for {url}")
        for listed in parser.records:
            if version is not None and not listing_may_match(listed, version, "patchstack", kind):
                continue
            listed.update(listing_page=1, listing_pages=1)
            links.setdefault(listed["url"], listed)
        status.status(listing_progress(1, count=len(links)))
    return list(links.values())


def fetch_product(client, kind, slug, version):
    if kind not in {"plugin", "theme"}:
        raise ValueError("Product type must be plugin or theme")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug, re.I):
        raise ValueError("Slug must contain only letters, numbers, dots, underscores, and hyphens")
    validate_version_threshold(version)
    return fetch_from_listing(client, kind, slug, version, f"/database/wordpress/{kind}/{quote(slug, safe='._-')}")


def fetch_core(client, target_version):
    validate_version_threshold(target_version)
    return fetch_from_listing(client, "core", "wordpress", target_version, None)


def fetch_from_listing(client, kind, slug, version, product_path):
    vulnerabilities, errors = [], []
    with vulnerability_progress() as status:
        links = listing_links(client, product_path, status=status, version=version, kind=kind)
        candidates = links
        for index, listed in enumerate(candidates, start=1):
            status.status(detail_progress(index, len(candidates)))
            def read_record():
                html = client.get(listed["url"], REQUEST_HEADERS).decode("utf-8", errors="replace")
                return parse_detail(html, listed["url"])
            record = read_detail_or_skip(read_record, index, len(candidates), listed["url"], status, errors)
            if record is None:
                continue
            vulnerabilities.append(record)
            status.status(detail_progress(index, len(candidates)))
        finish_detail_progress(status, len(candidates), errors)
    result = {"source": "Patchstack", "product_type": kind, "version": version,
              "url": CORE_LISTING_URL if kind == "core" else f"{BASE_URL}{product_path}/vulnerabilities", "vulnerabilities": vulnerabilities, "errors": errors, "complete": not errors}
    if kind == "core":
        result.update(records_scanned=len(links), detail_pages_checked=len(candidates))
    else:
        result["slug"] = slug
    return result
