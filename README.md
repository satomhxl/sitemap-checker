# Sitemap Checker

Monitor sitemap URLs, store first-seen pages in SQLite, and generate local reports for newly discovered pages.

Start here:

- `docs/GUIDE.md`: one-time setup guide for MacBook + Mac Mini + Hermes.
- `docs/RUNBOOK.md`: ongoing operating notes for humans and AI agents. Read this before making code or Git workflow changes.

## Sites

Current configs include the original game sites plus:

- `mediaio`: `media.io` and its locale sitemaps from `robots.txt`
- `pincel`: `pincel.app/sitemap.xml`, focused on `/tools/`, `/free/`, and `/media/` URLs
- `notegpt`: `notegpt.io/sitemap.xml` and `notegpt.io/sitemap_chatgpt.xml`

## Daily Local Report

Operational ownership:

- Mac Mini is the stable runtime environment. It generates `reports/` and pushes report files to GitHub.
- MacBook is the development and review environment. It pulls `reports/` from GitHub for reading, but should not normally generate or commit report files during development.
- Code changes from MacBook should normally stage source and docs only, not `reports/`.

Run this command from the project directory:

```bash
python3 run_daily_report.py
```

It checks `mediaio`, `pincel`, and `notegpt`, updates `sitemaps.db`, and writes a dated Markdown report:

```text
reports/YYYY-MM-DD.md
```

The first run should be treated as a baseline. After the baseline exists, later reports only include pages first seen during the selected window.

Useful options:

```bash
python3 run_daily_report.py --since-hours 24
python3 run_daily_report.py --site mediaio --site pincel --site notegpt
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --stdout
```

## Manual Checks

```bash
python3 checker.py --site mediaio --site pincel --site notegpt --show 10
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --since-hours 24
```
