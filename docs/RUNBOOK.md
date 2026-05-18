# Sitemap Checker Runbook

This document describes the intended daily workflow for this project. It is written for both humans and AI agents that may operate or modify the project later.

## Goal

Use sitemap monitoring to discover newly published pages on selected websites. The daily output should help identify keyword and demand signals from new URLs.

The current monitored non-game sites are:

- `mediaio`: `media.io`
- `pincel`: `pincel.app`

The project still contains the original game-site monitoring logic, but the daily operational focus is currently `mediaio` and `pincel`.

## Machine Roles

### MacBook

Primary development and review machine.

Use it to:

- Edit code and documentation.
- Commit and push source changes to GitHub.
- Pull generated reports from GitHub.
- Open the future lightweight Web dashboard locally.

### Mac Mini

Primary runtime machine.

Use it to:

- Pull the latest code from GitHub.
- Run the daily sitemap check.
- Generate daily local reports.
- Optionally commit and push generated report files back to GitHub.

## Data Flow

Recommended lightweight flow:

```text
MacBook edits code
  -> push to GitHub
Mac Mini pulls code
  -> runs daily report command
  -> updates local SQLite state
  -> writes Markdown report
  -> pushes report artifacts to GitHub
MacBook pulls latest artifacts
  -> reviews report or dashboard locally
```

## Important Files

Source files:

- `checker.py`: Fetches sitemap URLs, filters monitored URLs, and stores first-seen URLs in SQLite.
- `collect_new_pages.py`: Generates Markdown reports from first-seen URL rows.
- `run_daily_report.py`: Runs the daily `checker.py` plus `collect_new_pages.py` flow for `mediaio` and `pincel`.
- `collect_new_games.py`: Legacy game-name report helper.

Runtime state and artifacts:

- `sitemaps.db`: SQLite state database. It stores first-seen URL timestamps.
- `reports/YYYY-MM-DD.md`: Daily generated Markdown report.
- `logs/`: Legacy game report output when the GitHub Actions workflow is used.

Current recommendation:

- Keep `sitemaps.db` on the Mac Mini as runtime state.
- Push `reports/` to GitHub if you want GitHub to be the report archive.
- Do not rely on Telegram or chat messages as the only long-term archive.

Git policy:

- `.gitignore` excludes local SQLite state, WAL/SHM files, Python caches, macOS noise, and ad hoc logs.
- `reports/` is intentionally not ignored so the Mac Mini can push generated daily reports to GitHub.
- Source code should normally be changed on the MacBook, then pushed to GitHub for the Mac Mini to pull.
- Runtime artifacts should normally be generated on the Mac Mini.

## Daily Command

Run this from the project root on the Mac Mini:

```bash
python3 run_daily_report.py --site mediaio --site pincel --since-hours 24
```

This command:

- Fetches configured sitemaps for `mediaio` and `pincel`.
- Inserts newly discovered URLs into `sitemaps.db`.
- Generates a dated Markdown report in `reports/YYYY-MM-DD.md`.

## Baseline Behavior

The first run for a site should be treated as a baseline. A baseline records all currently known URLs so future reports can show only newly discovered pages.

If a site is added for the first time, expect a large first run. After the baseline exists, the daily report should normally be much smaller.

## Hermes Automation

Hermes can run the daily process on the Mac Mini.

Recommended high-level Hermes task:

```bash
git pull
python3 run_daily_report.py --site mediaio --site pincel --since-hours 24
git add reports
git commit -m "Update sitemap report"
git push
```

Before committing, Hermes should check whether there are actual report changes. If there are no changes, it should skip the commit and push.

Suggested safer shell flow:

```bash
git pull
python3 run_daily_report.py --site mediaio --site pincel --since-hours 24
git add reports
if ! git diff --cached --quiet; then
  git commit -m "Update sitemap report"
  git push
fi
```

If you decide to version `sitemaps.db`, add it explicitly to the `git add` command. Otherwise, keep it local to the Mac Mini.

The default repo policy is to keep `sitemaps.db` untracked. If a future workflow needs to share the DB baseline across machines, update `.gitignore` and this runbook deliberately instead of force-adding it casually.

## Dashboard Direction

The recommended UI direction is a lightweight local Web dashboard.

First version:

- Static HTML/CSS/JS.
- Read exported data from local files.
- Let the user select a site and view a timeline of newly discovered pages.
- Show keyword candidate, URL, and first-seen time.

Recommended future artifact for the dashboard:

```text
public/data/events.json
```

The current project already generates Markdown reports. A future AI agent can add a JSON export step to `collect_new_pages.py` or create a separate exporter, then build a static dashboard on top of that JSON.

Avoid starting with Electron, Tauri, or a backend API unless the dashboard grows beyond static-file needs.

## Adding A New Site

When adding a new site:

1. Check `https://example.com/robots.txt` for sitemap URLs.
2. Add a `SiteConfig` entry in `checker.py`.
3. Choose useful `include_prefixes` and `exclude_prefixes`.
4. Add keyword extraction behavior in `collect_new_pages.py` if the URL structure needs special handling.
5. Run a test with a temporary DB:

```bash
python3 checker.py --site SITE_NAME --db /private/tmp/sitemap-checker-test.db --show 5
python3 collect_new_pages.py --site SITE_NAME --db /private/tmp/sitemap-checker-test.db --since-hours 24 --stdout
```

6. Once verified, run the real baseline on the Mac Mini.

## AI Agent Notes

When operating this repo:

- Prefer `python3`, not `python`.
- Do not delete or reset `sitemaps.db` unless explicitly asked. It is stateful runtime data.
- Do not overwrite reports unless the user asks for regeneration.
- Keep generated reports separate from source-code changes when possible.
- If network access fails, check DNS and outbound network access in the host environment before rerunning.
- For daily usage, prefer `run_daily_report.py` over manually chaining lower-level scripts.
