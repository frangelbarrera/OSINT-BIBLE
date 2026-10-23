# scripts

Command-line utilities for working with the collection in this repository.
No API keys are required for the local utilities. Install the development dependencies from `requirements-dev.txt`; the link and username checks use `requests`, while data validation and README generation also use YAML/JSON-schema dependencies.

## Installation

```bash
python3 -m pip install -r requirements-dev.txt
```

## Scripts

| Name | Purpose | Input | Output |
|---|---|---|---|
| `link_checker.py` | Audits links in a Markdown file and classifies them as `OK`, `REDIRECT`, `BLOCKED`, `NO_RESPONSE` or `DEAD` | Markdown file | Summary on stdout; CSV optional |
| `dork_builder.py` | Builds passive-reconnaissance search queries for one or more domains | One or more domains | Query text on stdout or to a file |
| `username_check.py` | Checks whether a username route responds on supported platforms | One or more usernames | Table on stdout; CSV optional |

## Usage

```bash
python3 scripts/link_checker.py README.md audit/links-status.csv --all
python3 scripts/link_checker.py --repo audit/links-status.csv --all
python3 scripts/dork_builder.py --domain example.com --output all
python3 scripts/username_check.py torvalds --platforms github,keybase
```

## Important notes on behaviour

- `link_checker.py` and `username_check.py` **perform HTTP requests** in normal mode. Use `--limit` in the link checker to bound the number of URLs probed.
- Pass `--dry-run` to the link checker or username checker to list targets without making requests. `dork_builder.py` never makes requests; it only renders text.
- If no output path is given, `link_checker.py` writes nothing to disk; it only prints the summary.
- By default, the link-checker CSV contains only non-`OK` rows. Pass `--all` to include every unique URL, as used by the reports in `audit/`.
- Pass `--repo` to audit the README, all country Markdown files, documentation and this scripts guide in one run. The CSV records the first source file and line for each URL.
- `BLOCKED` results (`400`, `401`, `403`, `406`, `412`, `429`, `444`) usually indicate a WAF, geo-restriction or login wall. They are not automatically dead links and should be confirmed in a browser.
- `NO_RESPONSE` means the request could not be completed. Retry before changing or removing a link.
- `username_check.py` reports `UNKNOWN` when a platform blocks automated access. `FOUND` only means that the profile route responded; it does not confirm account ownership.
- Use these utilities only for lawful, authorized and ethical research.
