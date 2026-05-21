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
- `magichour`: `magichour.ai/sitemap-index.xml`, focused on tools, products, models, use cases, templates, and blog pages while excluding template detail inventory
- `airbrush`: `airbrush.com/sitemap.xml`, focused on tool and blog pages while excluding legal, FAQ, pricing, account, and app handoff pages
- `magnific`: weekly manual monitor for `magnific.com/ai-sitemap.xml` and `magnific.com/academy-sitemap.xml`, focused on AI tools and learning content rather than Freepik-style asset inventory

## Daily Local Report

Operational ownership:

- Mac Mini is the stable runtime environment. It generates `reports/` and pushes report files to GitHub.
- MacBook is the development and review environment. It pulls `reports/` from GitHub for reading, but should not normally generate or commit report files during development.
- Code changes from MacBook should normally stage source and docs only, not `reports/`.

Run this command from the project directory:

```bash
python3 run_daily_report.py
```

It checks `mediaio`, `pincel`, `notegpt`, `imgkits`, `magichour`, and `airbrush`, updates `sitemaps.db`, and writes a dated Markdown report:

```text
reports/YYYY-MM-DD.md
```

The first run should be treated as a baseline. After the baseline exists, later reports only include pages first seen during the selected window.

Useful options:

```bash
python3 run_daily_report.py --since-hours 24
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --stdout
```

## Manual Checks

```bash
python3 checker.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --show 10
python3 collect_new_pages.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --since-hours 24
```

## Weekly Manual Sitemap Import

Some relevant sites expose sitemap XML to a browser but reject script clients. For these sites, generate a weekly task, save the XML files by hand, then import the snapshot into the same SQLite history:

```bash
python3 manual_sitemap_task.py --site magnific --snapshot-date 2026-05-21
python3 import_manual_sitemaps.py --site magnific --snapshot-date 2026-05-21
python3 collect_new_pages.py --site magnific --since-hours 168 --stdout
```
