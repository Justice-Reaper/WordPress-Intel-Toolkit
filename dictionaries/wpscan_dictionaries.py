"""Collect slugs for vulnerable WordPress products listed by WPScan."""

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

from common.scraper_common import dictionary_progress, progress, save_slugs


BASE_DIR = Path(__file__).resolve().parents[1]
BASE_URL = "https://wpscan.com/"
PRODUCT_TYPES = {
    "plugin": ("plugins", re.compile(r"^/plugin/([^/]+)/?$")),
    "theme": ("themes", re.compile(r"^/theme/([^/]+)/?$")),
}
OUTPUT_DIRS = {
    "plugin": BASE_DIR / "wpscan" / "plugins",
    "theme": BASE_DIR / "wpscan" / "themes",
}


class ListingParser(HTMLParser):
    """Extract product slugs and the next-page link from a listing page."""

    def __init__(self, slug_pattern, current_url=BASE_URL):
        super().__init__(convert_charrefs=True)
        self.slug_pattern = slug_pattern
        self.current_url = current_url
        self.slugs = set()
        self.next_page = None

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attributes = dict(attrs)
        href = attributes.get("href")
        if not href:
            return
        classes = (attributes.get("class") or "").split()
        if "vulnerabilities__table--slug-link" in classes:
            product_url = urlparse(urljoin(self.current_url, href))
            if product_url.netloc not in {"wpscan.com", "a8cteam5105.wordpress.com"}:
                return
            path = product_url.path
            match = self.slug_pattern.fullmatch(path)
            if match:
                slug = match.group(1).strip().casefold()
                if slug:
                    self.slugs.add(slug)
        relations = (attributes.get("rel") or "").casefold().split()
        if "next" in relations:
            self.next_page = urljoin(self.current_url, href)


def listing_url(path, page=1):
    """Use the requested numbered listing with an always-empty get flag."""
    return f"{urljoin(BASE_URL, f'{path}/')}?page={page}&get"


def collect_slugs_by_type(client, kind):
    listing_path, slug_pattern = PRODUCT_TYPES[kind]
    slugs = set()
    url = listing_url(listing_path)
    page_number = 0

    with progress("", rate=0) as status:
        while url:
            page_number += 1
            status.status(dictionary_progress(kind, page_number, len(slugs)))
            response = client.get(url, {"Accept": "text/html,application/xhtml+xml"}).decode("utf-8", errors="replace")
            page = ListingParser(slug_pattern, url)
            page.feed(response)
            page.close()
            if not page.slugs and "vulnerabilities__table" not in response:
                raise RuntimeError(f"WPScan returned an unexpected listing for {url}")
            slugs.update(page.slugs)
            status.status(dictionary_progress(kind, page_number, len(slugs)))
            if not page.next_page:
                break
            next_url = urlparse(page.next_page)
            parameters = parse_qs(next_url.query, keep_blank_values=True)
            if next_url.path.rstrip("/") != "/" + listing_path or next_url.netloc not in {"wpscan.com", "a8cteam5105.wordpress.com"}:
                raise RuntimeError("WPScan returned a next-page link outside the selected listing")
            numbers = parameters.get("page", [])
            if len(numbers) != 1 or not numbers[0].isdigit() or int(numbers[0]) < 1:
                raise RuntimeError("WPScan returned an invalid next-page number")
            if any(value for value in parameters.get("get", [])):
                raise RuntimeError("WPScan pagination changed the empty get filter")
            url = listing_url(listing_path, int(numbers[0]))

        status.success(dictionary_progress(kind, page_number, len(slugs)))
    return slugs


def collect(client):
    results = {kind: collect_slugs_by_type(client, kind) for kind in PRODUCT_TYPES}
    for kind, directory in OUTPUT_DIRS.items():
        save_slugs(directory / "slugs.txt", results[kind])
    return {"plugins": results["plugin"], "themes": results["theme"]}
