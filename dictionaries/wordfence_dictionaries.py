"""Collect WordPress slugs from Wordfence Intelligence vulnerability listings."""

import re
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

from common.scraper_common import dictionary_progress, progress, save_slugs
from vulnerabilities.sources.wordfence import load_rendered_page, parse_html_text, sync_playwright, PlaywrightError


BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUTS = {
    "plugin": ("wordpress-plugins", BASE_DIR / "wordfence" / "plugins"),
    "theme": ("wordpress-themes", BASE_DIR / "wordfence" / "themes"),
}
BASE_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/"
SLUG_PATH = re.compile(r"^/threat-intel/vulnerabilities/wordpress-(?:plugins|themes)/([^/]+)/?$")


class ProductLinksParser(HTMLParser):
    """Extract product slugs and the last page number from a listing page."""

    def __init__(self, listing_path=None):
        super().__init__(convert_charrefs=True)
        self.listing_path = "/threat-intel/vulnerabilities/" + listing_path if listing_path else None
        self.slugs = set()
        self.last_page = 1

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if not href:
            return
        origin = BASE_URL + self.listing_path.rsplit("/", 1)[-1] if self.listing_path else BASE_URL
        url = urljoin(origin, href)
        parsed = urlparse(url)
        if parsed.netloc == "www.wordfence.com":
            match = SLUG_PATH.fullmatch(parsed.path)
            if match and (self.listing_path is None or parsed.path.startswith(self.listing_path + "/")):
                self.slugs.add(match.group(1).strip().casefold())
        if parsed.netloc != "www.wordfence.com" or (self.listing_path is not None and parsed.path.rstrip("/") != self.listing_path):
            return
        for value in parse_qs(parsed.query).get("page", []):
            if value.isdigit():
                self.last_page = max(self.last_page, int(value))


def collect_slugs(client, kind, listing_path):
    listing_url = urljoin(BASE_URL, listing_path)
    slugs = set()
    with progress("", rate=0) as status:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=not getattr(client, "show_browser", False))
                try:
                    page = browser.new_page(locale="en-US")
                    number, last_page = 1, 1
                    while number <= last_page:
                        url = f"{listing_url}?sortby=date&sort=desc&page={number}"
                        def ready(html):
                            parser = ProductLinksParser(listing_path)
                            parser.feed(html)
                            return bool(parser.slugs)
                        status.status(dictionary_progress(kind, number, len(slugs)))
                        html = load_rendered_page(page, url, ready, client=client, on_wait=lambda _message: status.status(dictionary_progress(kind, number, len(slugs))))
                        parser = ProductLinksParser(listing_path)
                        parser.feed(html)
                        slugs.update(parser.slugs)
                        last_page = max(last_page, parser.last_page)
                        count = re.search(r"Showing\s+([\d,]+)\s*[-–]\s*([\d,]+)\s+of\s+([\d,]+)", parse_html_text(html), re.I)
                        if number == 1 and count:
                            first, last, total = [int(v.replace(",", "")) for v in count.groups()]
                            if last >= first:
                                last_page = max(last_page, (total + last - first) // (last - first + 1))
                        status.status(dictionary_progress(kind, number, len(slugs)))
                        number += 1
                        if client.delay:
                            time.sleep(client.delay)
                finally:
                    browser.close()
        except PlaywrightError as error:
            raise RuntimeError(f"Could not load Wordfence in bundled Chromium: {error}") from error
        status.success(dictionary_progress(kind, number - 1, len(slugs)))
    return slugs


def collect(client):
    results = {
        kind: collect_slugs(client, kind, listing_path)
        for kind, (listing_path, _directory) in OUTPUTS.items()
    }
    for kind, (_listing_path, directory) in OUTPUTS.items():
        save_slugs(directory / "slugs.txt", results[kind])
    return {"plugins": results["plugin"], "themes": results["theme"]}
