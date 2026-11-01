"""Collect WordPress plugin and theme slugs from Patchstack's global web listings."""

import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from common.scraper_common import dictionary_progress, progress, save_slugs
from vulnerabilities.sources.patchstack import iter_global_listing_pages


BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIRS = {
    "plugin": BASE_DIR / "patchstack" / "plugins",
    "theme": BASE_DIR / "patchstack" / "themes",
}


def collect_wordpress_slugs(client):
    slugs_by_type = {kind: set() for kind in OUTPUT_DIRS}
    for kind in OUTPUT_DIRS:
        slugs = slugs_by_type[kind]
        number = 0
        with progress("", rate=0) as status:
            pages = iter_global_listing_pages(client, kind, on_page=lambda n: status.status(dictionary_progress(kind, n, len(slugs))))
            try:
                for number, records in pages:
                    for record in records:
                        path = urlparse(record["url"]).path
                        match = re.fullmatch(rf"/database/wordpress/{kind}/([^/]+)/vulnerability/[^/]+/?", path)
                        if match:
                            slug = unquote(match.group(1)).strip().casefold()
                            if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug):
                                slugs.add(slug)
                    status.status(dictionary_progress(kind, number, len(slugs)))
            finally:
                pages.close()
            status.success(dictionary_progress(kind, number, len(slugs)))
    return slugs_by_type


def save_dictionaries(slugs_by_type):
    for kind, directory in OUTPUT_DIRS.items():
        save_slugs(directory / "slugs.txt", slugs_by_type[kind])


def collect(client):
    results = collect_wordpress_slugs(client)
    save_dictionaries(results)
    return {"plugins": results["plugin"], "themes": results["theme"]}
