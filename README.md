# Sitemap Checker

Monitor sitemap URLs for SEO-driven websites, store first-seen pages in SQLite, and generate local reports for newly discovered pages that may reveal keyword demand and content trends.

Start here:

- `docs/GUIDE.md`: one-time setup guide for MacBook + Mac Mini + Hermes.
- `docs/RUNBOOK.md`: ongoing operating notes for humans and AI agents. Read this before making code or Git workflow changes.

## Sites

This project is not a general sitemap monitor. It is meant to watch SEO-focused sites that publish landing pages, tool pages, articles, templates, or other indexable pages to capture organic-search demand. Avoid adding pure directory, catalog, marketplace, or database-listing sites when their new URLs mostly reflect inventory churn rather than SEO topic strategy.

Current configs include the original game sites plus:

- `mediaio`: `media.io` and its locale sitemaps from `robots.txt`
- `pincel`: `pincel.app/sitemap.xml`, focused on `/tools/`, `/free/`, and `/media/` URLs
- `notegpt`: `notegpt.io/sitemap.xml` and `notegpt.io/sitemap_chatgpt.xml`
- `imgkits`: `imgkits.com/sitemap_index.xml` and its locale sitemaps

## Daily Local Report

Operational ownership:

- Mac Mini is the stable runtime environment. It generates `reports/` and pushes report files to GitHub.
- MacBook is the development and review environment. It pulls `reports/` from GitHub for reading, but should not normally generate or commit report files during development.
- Code changes from MacBook should normally stage source and docs only, not `reports/`.

Run this command from the project directory:

```bash
python3 run_daily_report.py
```

It checks `mediaio`, `pincel`, `notegpt`, and `imgkits`, updates `sitemaps.db`, and writes a dated Markdown report:

```text
reports/YYYY-MM-DD.md
```

The first run should be treated as a baseline. After the baseline exists, later reports only include pages first seen during the selected window.

Useful options:

```bash
python3 run_daily_report.py --since-hours 24
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --site imgkits
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --site imgkits --stdout
```

## Manual Checks

```bash
python3 checker.py --site mediaio --site pincel --site notegpt --site imgkits --show 10
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --site imgkits --since-hours 24
```
