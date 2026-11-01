# WordPress Intel Toolkit

WordPress security intelligence toolkit for building plugin and theme wordlists and researching Core, plugin, and theme vulnerabilities across Wordfence, WPScan, and Patchstack

## Features

### Dictionary Generation

Collects plugin and theme slugs from WordPress.org, Wordfence, WPScan, and Patchstack. Creates separate dictionaries for each source and two combined dictionaries without duplicate slugs

### Popularity Ordering

Requests WordPress.org plugins and themes by popularity and preserves that order. Combined dictionaries place WordPress.org results first, followed by additional slugs from the other sources in alphabetical order

### Vulnerability Research

Looks up a plugin or theme by slug and version, or WordPress Core by version. Filters listing entries before opening individual vulnerability pages and extracts the report fields from those pages

### Readable Reports

Saves severity counts, target, sources, completion status, and full vulnerability details to reports, sorted by CVSS. Combined reports deduplicate valid CVEs using the priority Patchstack, Wordfence, then WPScan. Records without a CVE remain separate. A horizontal separator and blank space separate vulnerability blocks

## Installation

Use Python 3.10 or newer

```
git clone https://github.com/Justice-Reaper/WordPress-Intel-Toolkit.git
cd WordPress-Intel-Toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If Chromium reports missing system libraries on a supported Linux distribution:

```
python -m playwright install-deps chromium
```

Activate the environment with `source .venv/bin/activate` in each new terminal

## Help Panels

### Dictionary Builder

```
$ python build_wordpress_dictionaries.py -h
usage: build_wordpress_dictionaries.py [options]

General options:
  -h, --help                                  show this help message and exit

Sources:
  --sources SOURCE,SOURCE,...                 Sources: wordpress-org, wordfence, wpscan, patchstack (comma-separated, default: all)

Request settings:
  --timeout-between-requests SECONDS          Pause between successful requests or page loads (default: 1 second)
  --request-timeout SECONDS                   HTTP connection/read timeout (default: 30 seconds, HTTP sources only)
  --retry-delay-on-non-200 SECONDS            Pause before retrying a failed load (default: 30 seconds, 0 disables the pause)
  --max-retries-on-non-200 COUNT              Retries after the first attempt (default: 3, 0 disables retries)
  --infinite-retries-on-non-200               Retry without a limit (default: disabled)

Browser settings:
  --show-browser                              Open a visible Chromium window (default: headless, Wordfence and Patchstack dictionaries)
  --page-load-timeout SECONDS                 Maximum navigation time per attempt (default: 15 seconds)
  --browser-wait-timeout SECONDS              Maximum wait for page HTML per attempt (default: 15 seconds)
```

### Vulnerability Lookup

```
$ python lookup_wordpress_vulnerabilities.py -h
usage: lookup_wordpress_vulnerabilities.py [options]

General options:
  -h, --help                                  show this help message and exit

Target (choose one):
  --plugin SLUG                               Plugin slug to query
  --theme SLUG                                Theme slug to query
  --core-version VERSION                      WordPress Core version threshold

Version filter:
  --version VERSION                           Minimum affected-version threshold (required with --plugin or --theme)

Sources:
  --sources SOURCE,SOURCE,...                 Sources: patchstack, wordfence, wpscan (default: all)

Request settings:
  --timeout-between-requests SECONDS          Pause between successful requests or page loads (default: 1 second)
  --request-timeout SECONDS                   HTTP connection/read timeout (default: 30 seconds, HTTP sources only)
  --retry-delay-on-non-200 SECONDS            Pause before retrying a failed load (default: 30 seconds, 0 disables the pause)
  --max-retries-on-non-200 COUNT              Retries after the first attempt (default: 3, 0 disables retries)
  --infinite-retries-on-non-200               Retry without a limit (default: disabled)

Browser settings:
  --show-browser                              Open a visible Chromium window (default: headless, Wordfence and Patchstack Core)
  --page-load-timeout SECONDS                 Maximum navigation time per attempt (default: 15 seconds)
  --browser-wait-timeout SECONDS              Maximum wait for page HTML per attempt (default: 15 seconds)
```

## Usage

### Generate Dictionaries

Use all sources:

```
python build_wordpress_dictionaries.py
```

Use only WordPress.org, or choose multiple sources:

```
python build_wordpress_dictionaries.py --sources wordpress-org
python build_wordpress_dictionaries.py --sources wordpress-org,wordfence
```

| File | Contents |
| --- | --- |
| `<source>/plugins/slugs.txt` | Unique plugin slugs from that source |
| `<source>/themes/slugs.txt` | Unique theme slugs from that source |
| `combined/plugins/slugs.txt` | Combined plugin dictionary |
| `combined/themes/slugs.txt` | Combined theme dictionary |

Running the builder again replaces the selected sources' dictionaries and the combined dictionaries. Combined files use only the sources selected in that run

Use the generated dictionaries with ffuf, replacing `<IP>` with the target host and `<WORDLIST>` with a dictionary path

```
ffuf -u http://<IP>/FUZZ/ -w <WORDLIST> -c
```

### Look Up Vulnerabilities

Choose one target. Plugins and themes require `--version`, Core takes its version through `--core-version`:

```
python lookup_wordpress_vulnerabilities.py --plugin publishpress-authors --version 4.17.0
python lookup_wordpress_vulnerabilities.py --theme 15zine --version 3.0
python lookup_wordpress_vulnerabilities.py --core-version 6.8.5
```

Choose specific sources:

```
python lookup_wordpress_vulnerabilities.py --core-version 6.8.5 --sources wordfence
python lookup_wordpress_vulnerabilities.py --plugin publishpress-authors --version 4.17.0 --sources patchstack,wpscan
```

The supplied version is a threshold: affected ranges reaching that version or a later version are included. For example, `<= 6.8.5` and `6.9 - 7.1.3` qualify for `6.8.5`, while `< 6.8.5` does not. This is a threshold search, not an exact installed-version assessment

Reports are saved after each source finishes, followed by a combined report. Plugin/theme reports are stored under `results/<type>/<slug>/<version>/`, Core reports use `results/core/<version>/`. Each file has a timestamp and unique identifier, so previous reports are retained. Failed sources or details produce a `Partial` result while preserving the successfully collected information

The terminal shows progress and saved report paths. The summary and full vulnerability details are included only in the report files. Open a saved report with:

```
less "/path/to/combined-report.txt"
```

## Dictionary Sources

| Source | Type | URL |
| --- | --- | --- |
| WordPress.org | Plugins | `https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=popular&request[page]=1&request[per_page]=100&request[fields][description]=false&request[fields][sections]=false` |
| WordPress.org | Themes | `https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[browse]=popular&request[page]=1&request[per_page]=100&request[fields][description]=false&request[fields][sections]=false` |
| Wordfence | Plugins | `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins?sortby=date&sort=desc&page=1` |
| Wordfence | Themes | `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes?sortby=date&sort=desc&page=1` |
| WPScan | Plugins | `https://wpscan.com/plugins/?page=1&get` |
| WPScan | Themes | `https://wpscan.com/themes/?page=1&get` |
| Patchstack | Plugins | `https://patchstack.com/database?platform=wordpress&type=plugin&page=1` |
| Patchstack | Themes | `https://patchstack.com/database?platform=wordpress&type=theme&page=1` |

## Vulnerability Sources

| Source | Type | URL |
| --- | --- | --- |
| Wordfence | Plugin | `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/publishpress-authors` |
| Wordfence | Theme | `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/newsmatic` |
| Wordfence | Core | `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core?sortby=date&sort=desc&page=1` |
| WPScan | Plugin | `https://wpscan.com/plugin/publishpress-authors/` |
| WPScan | Theme | `https://wpscan.com/theme/15zine/` |
| WPScan | Core | `https://wpscan.com/wordpresses/?page=1` |
| Patchstack | Plugin | `https://patchstack.com/database/wordpress/plugin/publishpress-authors/vulnerabilities` |
| Patchstack | Theme | `https://patchstack.com/database/wordpress/theme/15zine/vulnerabilities` |
| Patchstack | Core | `https://patchstack.com/database?platform=wordpress&type=core&page=1` |

## Vulnerability Fields

| Field | Contents |
| --- | --- |
| `title` | Vulnerability title |
| `status` | Patch status |
| `cve_id` | CVE identifier |
| `cvss` | Numeric CVSS score, when available |
| `severity` | Severity computed locally from CVSS |
| `date` | Published date provided by the source |
| `affected_versions` | Affected version ranges, displayed as comma-separated values |
| `patched_versions` | Patched versions, displayed as comma-separated values |
| `software_type` | Plugin, Theme, or Core |
| `software_slug` | Software slug identified on the detail page |
| `link` | URL of the individual vulnerability detail page |

`Unknown` means the field could not be obtained from that source's detail page. For example, a vulnerability may have no published CVE. Missing or invalid CVSS scores appear as `Unknown`, with severity `Unrated`. Missing values are not copied from another source or a related vulnerability

## Project Structure

```
WordPress-Intel-Toolkit/
├── build_wordpress_dictionaries.py
├── lookup_wordpress_vulnerabilities.py
├── dictionaries/                 # Four internal slug collector modules
├── vulnerabilities/              # Internal vulnerability package
│   └── sources/                  # Three shared source implementations
├── common/
│   ├── scraper_common.py         # Requests, shared CLI options and progress
│   └── output.py                 # Reports, deduplication and persistence
├── README.md
├── requirements.txt
└── .gitignore
```
