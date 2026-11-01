"""Collect slugs from the public WordPress.org plugin and theme directories."""

import json
import math
from pathlib import Path
from urllib.parse import urlencode

from common.scraper_common import dictionary_progress, progress, save_slugs


BASE_DIR = Path(__file__).resolve().parents[1]
PER_PAGE = 100
API_URLS = {
    "plugins": "https://api.wordpress.org/plugins/info/1.2/",
    "themes": "https://api.wordpress.org/themes/info/1.2/",
}


def collect_slugs(client, kind):
    slugs = {}
    page_number = 1
    total_pages = None
    total_results = 0

    with progress("", rate=0) as status:
        while total_pages is None or page_number <= total_pages:
            status.status(dictionary_progress(kind, page_number, len(slugs), total_results if total_pages is not None else None))
            query = urlencode({
                "action": f"query_{kind}",
                "request[browse]": "popular",
                "request[page]": page_number,
                "request[per_page]": PER_PAGE,
                "request[fields][description]": "false",
                "request[fields][sections]": "false",
            })
            url = f"{API_URLS[kind]}?{query}"
            body = client.get(url, {"Accept": "application/json"})
            data = json.loads(body.decode("utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get(kind), list) or not isinstance(data.get("info"), dict):
                raise RuntimeError(f"WordPress.org returned an unexpected {kind} response on page {page_number}")
            items = data[kind]
            info = data["info"]
            if any(not isinstance(item, dict) for item in items):
                raise RuntimeError("WordPress.org returned invalid product records")
            if any(not isinstance(item.get("slug"), str) for item in items):
                raise RuntimeError("WordPress.org returned a product without a valid slug")
            total_results = int(info.get("results") or 0)
            total_pages = int(info.get("pages") or (math.ceil(total_results / PER_PAGE) if total_results else page_number))

            if total_pages < 1 or total_results < 0:
                raise RuntimeError("WordPress.org returned invalid pagination totals")

            for item in items:
                slug = (item.get("slug") or "").strip().casefold()
                if slug and "/" not in slug and "\\" not in slug:
                    slugs.setdefault(slug, None)

            status.status(dictionary_progress(kind, page_number, len(slugs), total_results))
            if page_number >= total_pages:
                break
            page_number += 1

        if not slugs:
            raise RuntimeError(f"The official WordPress.org API returned no {kind} slugs.")
        status.success(dictionary_progress(kind, page_number, len(slugs), total_results))
    return list(slugs)


def collect(client):
    results = {kind: collect_slugs(client, kind) for kind in API_URLS}
    for kind, slugs in results.items():
        save_slugs(BASE_DIR / "wordpress-org" / kind / "slugs.txt", slugs, preserve_order=True)
    return {"plugins": results["plugins"], "themes": results["themes"]}
