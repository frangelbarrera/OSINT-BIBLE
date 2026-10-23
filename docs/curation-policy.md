**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-20
**Scope:** sources, country files, tools, scripts, freshness, duplicates, and link validation.

| Field | Current record |
|---|---|
| Status | Documentation repository with auxiliary scripts; `repo-health.yml` validates data and freshness, and `lychee.yml` checks links. |
| Evidence | `data/`, `countries/`, `scripts/`, `schema/`, `.github/workflows/repo-health.yml`, `.github/workflows/lychee.yml`, `SECURITY.md`. |
| Verification | Run the repository validation workflow, use `python3 scripts/link_checker.py --repo ... --all` for a full local audit, and review link-check artifacts; record source verification dates where practical. |
| Owner | Repository owner and contributors. |
| Limitations | Link availability does not prove source accuracy, safety, or authorization. |

Review sources for relevance, provenance, freshness, duplication, accessibility, and dual-use risk. Do not include credentials or private data.
