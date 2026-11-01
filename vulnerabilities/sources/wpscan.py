"""Look up plugin, theme, or WordPress Core vulnerabilities on WPScan."""

import re
from contextlib import nullcontext
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from common.scraper_common import vulnerability_progress, listing_progress, validate_version_threshold, product_listing_ranges, listing_may_match, read_detail_or_skip, finish_detail_progress, core_listing_ranges, detail_progress, validate_vulnerability


BASE_URL = "https://wpscan.com/"
CORE_LISTING_URL = urljoin(BASE_URL, "wordpresses/?page=1")
VULNERABILITY_PATH = re.compile(r"/vulnerability/([^/]+)/?$")
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
}


def clean(value):
    return " ".join(value.split())


class ProductParser(HTMLParser):
    """Read vulnerability detail links and titles from product or Core listings."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.by_url = {}
        self.anchor = None

    @property
    def records(self):
        return self.rows

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href", "")
        if tag != "a" or not href:
            return
        url = urljoin(BASE_URL, href)
        parsed = urlparse(url)
        if parsed.netloc in {"wpscan.com", "a8cteam5105.wordpress.com"} and VULNERABILITY_PATH.fullmatch(parsed.path):
            canonical = urljoin(BASE_URL, parsed.path.rstrip("/") + "/")
            if canonical not in self.by_url:
                record = {"url": canonical, "listing_text": ""}
                self.rows.append(record)
                self.by_url[canonical] = record
            self.anchor = {"record": self.by_url[canonical], "text": []}


    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            text = " ".join(" ".join(self.anchor["text"]).split())
            if len(text) > len(self.anchor["record"]["listing_text"]):
                self.anchor["record"]["listing_text"] = text
            self.anchor = None


class CoreListingParser(HTMLParser):
    """Extract vulnerability links and the next listing page."""

    def __init__(self, listing_url=CORE_LISTING_URL):
        super().__init__(convert_charrefs=True)
        self.listing_url = listing_url
        self.listing_path = urlparse(listing_url).path.rstrip("/")
        self.row_parser = ProductParser()
        self.next_page = None

    @property
    def records(self):
        return self.row_parser.rows

    def handle_starttag(self, tag, attrs):
        self.row_parser.handle_starttag(tag, attrs)
        attributes = dict(attrs)
        href = attributes.get("href", "")
        rel = (attributes.get("rel") or "").casefold().split()
        if tag == "a" and "next" in rel and href:
            candidate = urljoin(self.listing_url, href)
            if urlparse(candidate).netloc not in {"wpscan.com", "a8cteam5105.wordpress.com"}:
                raise RuntimeError("WPScan returned an external next-page link")
            if urlparse(candidate).path.rstrip("/") != self.listing_path:
                raise RuntimeError("WPScan pagination left the selected listing")
            self.next_page = candidate

    def handle_endtag(self, tag):
        self.row_parser.handle_endtag(tag)

    def handle_data(self, data):
        self.row_parser.handle_data(data)


class VulnerabilityDetailParser(HTMLParser):
    """Collect the requested fields from an individual WPScan vulnerability page."""

    BLOCK_TAGS = {"br", "dd", "div", "dt", "h1", "h2", "h3", "h4", "li", "p", "section", "td", "th", "tr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.title_parts = []
        self.in_title = False
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"script", "style", "svg", "noscript"}:
            self.ignored_depth += 1
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "h1" and not self.title_parts:
            self.in_title = True

    def handle_endtag(self, tag):
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")
        if tag in {"script", "style", "svg", "noscript"} and self.ignored_depth:
            self.ignored_depth -= 1
        if tag == "h1" and self.in_title:
            self.in_title = False

    def handle_data(self, data):
        if not self.ignored_depth:
            self.parts.append(data)
            if self.in_title:
                self.title_parts.append(data)

    @property
    def lines(self):
        return [clean(line) for line in "".join(self.parts).splitlines() if clean(line)]

    @property
    def title(self):
        return clean("".join(self.title_parts))


class SoftwareRowsParser(HTMLParser):
    """Read software identity and fixed versions from individual detail rows."""
    VOID = {"br", "img", "input", "hr", "meta", "link", "wbr", "source"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.row = None
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "vulnerabilities-single__affects-row" in attrs.get("class", "").split():
            self.row = {"type": "", "slug": "", "text": []}
            self.depth = 0
        if self.row is None:
            return
        if tag not in self.VOID:
            self.depth += 1
        self.row["text"].append(" ")
        if tag == "a":
            identity = re.fullmatch(r"/(plugin|theme|wordpress)/([^/]+)/?", urlparse(attrs.get("href", "")).path)
            if identity:
                kind, slug = identity.groups()
                self.row["type"] = "core" if kind == "wordpress" else kind
                self.row["slug"] = "wordpress" if kind == "wordpress" else slug

    def handle_data(self, value):
        if self.row is not None:
            self.row["text"].append(value)

    def handle_endtag(self, tag):
        if self.row is not None and tag not in self.VOID:
            self.depth -= 1
            self.row["text"].append(" ")
            if self.depth == 0:
                self.rows.append(self.row)
                self.row = None


DETAIL_LABELS = (
    "description", "affects plugins", "affects themes", "affects wordpress",
    "fixed in", "references", "cve", "url", "classification", "type",
    "owasp top 10", "cwe", "cvss", "miscellaneous", "original researcher",
    "verified", "wpvdb id", "timeline", "publicly published", "added",
    "last updated", "other",
)


def detail_field(lines, label):
    wanted = label.casefold().rstrip(":")
    for index, line in enumerate(lines):
        normalized = line.casefold().rstrip(":")
        if normalized == wanted:
            for value in lines[index + 1:]:
                if value.casefold().rstrip(":") in DETAIL_LABELS:
                    break
                if value:
                    return value
            return ""
        if normalized.startswith(wanted + " ") or normalized.startswith(wanted + ":"):
            return re.sub(r"^" + re.escape(label) + r"\s*:?[ \t]*", "", line, flags=re.IGNORECASE).strip()
    return ""


def version_expressions(title):
    recognized = core_listing_ranges(title, "wpscan") or product_listing_ranges(title, "wpscan")
    if recognized:
        return recognized
    version = r"\d+(?:\.\d+){1,3}"
    interval = re.search(rf"(?<![\w.])({version})\s*[-–]\s*({version})(?=\s*[-–])", title)
    if interval:
        return [f"{interval.group(1)} - {interval.group(2)}"]
    comparison = re.search(rf"(?<![\w.])(<=|<|>=|>)\s*({version})", title)
    if comparison:
        return [f"{comparison.group(1)} {comparison.group(2)}"]
    exact = re.search(rf"(?<![\w.])({version})(?=\s+[-–])", title)
    return [exact.group(1)] if exact else []


def parse_vulnerability_detail(html, product_type=None, slug=None):
    parser = VulnerabilityDetailParser()
    parser.feed(html)
    parser.close()
    lines = parser.lines
    title = parser.title
    cve = detail_field(lines, "CVE")
    cve_match = re.search(r"\bCVE-\d{4}-\d+\b", cve, re.IGNORECASE)
    cvss = detail_field(lines, "CVSS")
    cvss_match = re.search(r"\d+(?:\.\d+)?(?:\s*\([^)]*\))?", cvss)
    published = detail_field(lines, "Publicly Published")
    affected_plugin = detail_field(lines, "Affects Plugins")
    affected_theme = detail_field(lines, "Affects Themes")
    affected_wordpress = detail_field(lines, "Affects WordPress")
    if not any((affected_plugin, affected_theme, affected_wordpress)) and "vulnerabilities-single__" not in html and not version_expressions(title):
        raise RuntimeError("WPScan returned a page without software details")
    selected_type = product_type or ("core" if affected_wordpress else ("plugin" if affected_plugin else "theme"))
    section_label = {"core": "Affects WordPress", "plugin": "Affects Plugins", "theme": "Affects Themes"}[selected_type]
    section_lines = []
    active = False
    for line in lines:
        if line.casefold() == section_label.casefold():
            active = True
            continue
        if active and line.casefold() in {"affects plugins", "affects themes", "affects wordpress", "references", "classification", "timeline", "miscellaneous"}:
            break
        if active:
            section_lines.append(line)
    patched_versions = []
    for line in section_lines:
        if re.match(r"^Fixed in\b", line, re.I):
            patched_versions.extend(re.findall(r"\d+(?:\.\d+){1,3}", line))
    date_match = re.search(r"\d{4}-\d{2}-\d{2}", published)
    if selected_type == "core" and affected_wordpress:
        software_type, software_slug = "Core", "wordpress"
    elif selected_type == "plugin" and affected_plugin:
        software_type, software_slug = "Plugin", affected_plugin.split()[0]
    elif selected_type == "theme" and affected_theme:
        software_type, software_slug = "Theme", affected_theme.split()[0]
    else:
        software_type, software_slug = "", ""
    rows = SoftwareRowsParser()
    rows.feed(html)
    matching = [row for row in rows.rows if row["type"] == selected_type and (slug is None or row["slug"].casefold() == slug.casefold())]
    available_rows = [row for row in rows.rows if row["type"] == selected_type]
    if slug is not None and available_rows and not matching:
        raise RuntimeError("WPScan detail identifies different software from the requested slug")
    status_text = " ".join(section_lines)
    if matching:
        software_type = {"core": "Core", "plugin": "Plugin", "theme": "Theme"}[matching[0]["type"]]
        software_slug = matching[0]["slug"]
        status_text = " ".join(clean("".join(row["text"])) for row in matching)
        patched_versions = []
        for row in matching:
            patched_versions.extend(re.findall(r"Fixed in(?: WordPress)?\s+(\d+(?:\.\d+){1,3})", clean("".join(row["text"])), re.I))
    elif product_type is not None and slug is not None and software_slug and software_slug.casefold() != slug.casefold():
        raise RuntimeError("WPScan detail does not identify the requested software")
    title_is_core = bool(re.match(r"^(?:WP|WordPress(?: Core)?)\s+(?:[<>]=?\s*)?\d", title, re.I))
    affected_versions = version_expressions(title) if selected_type == "core" or not title_is_core else []
    if not affected_versions:
        affected_versions = list(dict.fromkeys(line for line in section_lines if re.fullmatch(r"(?:[<>]=?\s*)?\d+(?:\.\d+){1,3}(?:\s*[-–]\s*\d+(?:\.\d+){1,3})?", line)))
    return validate_vulnerability({
        "title": title,
        "status": "Patched" if patched_versions else ("Unpatched" if re.search(r"not fixed|unfixed|unpatched", status_text, re.I) else "Unknown"),
        "cve_id": cve_match.group(0) if cve_match else "Unknown",
        "cvss": cvss_match.group(0) if cvss_match else "",
        "date": date_match.group(0) if date_match else published,
        "affected_versions": affected_versions,
        "patched_versions": list(dict.fromkeys(patched_versions)),
        "software_type": software_type,
        "software_slug": software_slug,
    })


def fetch_detail(client, listed, product_type=None, slug=None):
    html = client.get(listed["url"], REQUEST_HEADERS).decode("utf-8", errors="replace")
    return parse_vulnerability_detail(html, product_type, slug)


def listing_links(client, url, status=None, version=None, kind="core"):
    """Follow Next for Core; read each plugin/theme listing once."""
    page_number, links = 0, {}
    with (nullcontext(status) if status is not None else vulnerability_progress()) as status:
        while url:
            page_number += 1
            status.status(listing_progress(page_number, count=len(links)))
            html = client.get(url, REQUEST_HEADERS).decode("utf-8", errors="replace")
            parser = CoreListingParser(url) if kind == "core" else ProductParser()
            parser.feed(html)
            parser.close()
            if not parser.records and "vulnerabilities__table" not in html:
                raise RuntimeError(f"WPScan returned an unexpected listing for {url}")
            for record in parser.records:
                if version is not None and not listing_may_match(record, version, "wpscan", kind):
                    continue
                record["listing_page"] = page_number
                links.setdefault(record["url"], record)
            status.status(listing_progress(page_number, count=len(links)))
            url = parser.next_page if kind == "core" else None
        for record in links.values():
            record["listing_pages"] = page_number
    return list(links.values()), page_number


def fetch_product(client, kind, slug, version):
    if kind not in {"plugin", "theme"}:
        raise ValueError("Product type must be plugin or theme")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug, re.I):
        raise ValueError("Slug must contain only letters, numbers, dots, underscores, and hyphens")
    validate_version_threshold(version)
    return fetch_from_listing(client, kind, slug, version, urljoin(BASE_URL, f"{kind}/{slug}/"))


def fetch_core(client, version):
    validate_version_threshold(version)
    return fetch_from_listing(client, "core", "wordpress", version, CORE_LISTING_URL)


def fetch_from_listing(client, kind, slug, version, url):
    vulnerabilities, errors = [], []
    with vulnerability_progress() as status:
        links, pages = listing_links(client, url, status=status, version=version, kind=kind)
        candidates = links
        for index, listed in enumerate(candidates, start=1):
            status.status(detail_progress(index, len(candidates)))
            record = read_detail_or_skip(lambda: fetch_detail(client, listed, kind, slug), index, len(candidates), listed["url"], status, errors)
            if record is None:
                continue
            vulnerabilities.append(record)
            status.status(detail_progress(index, len(candidates)))
        finish_detail_progress(status, len(candidates), errors)
    result = {"source": "WPScan", "product_type": kind, "version": version, "url": url, "vulnerabilities": vulnerabilities, "errors": errors, "complete": not errors}
    if kind == "core":
        result["pages_scanned"] = pages
    else:
        result["slug"] = slug
    return result
