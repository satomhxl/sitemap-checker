# Sitemap Checker Runbook

This document describes the intended daily workflow for this project. It is written for both humans and AI agents that may operate or modify the project later.

## Goal

Use sitemap monitoring to discover newly published pages on selected SEO-driven websites. The daily output should help identify keyword demand, content strategy, and emerging topic signals from new indexable URLs.

This is not intended to be a broad sitemap archive or a directory-site crawler. The monitored sites should be selected because their new pages are likely to reveal organic-search strategy: landing pages, tool pages, articles, templates, comparison pages, or other content built to capture search demand.

Avoid adding sites where sitemap changes mostly represent inventory churn or database growth, such as pure directories, catalogs, marketplaces, app listings, product databases, or generic index pages. Those sites can create a lot of low-signal URLs without telling us much about SEO topic strategy.

The current monitored non-game sites are:

- `mediaio`: `media.io`
- `pincel`: `pincel.app`
- `notegpt`: `notegpt.io`
- `imgkits`: `imgkits.com`
- `magichour`: `magichour.ai`
- `airbrush`: `airbrush.com`
- `kittl`: `kittl.com`
- `magnific`: `magnific.com` (weekly manual import because script clients may receive 403)

The project still contains the original game-site monitoring logic, but the daily automatic focus is currently `mediaio`, `pincel`, `notegpt`, `imgkits`, `magichour`, `airbrush`, and `kittl`. `magnific` is monitored through the weekly manual sitemap import flow.

## Machine Roles

Before modifying this project, read this runbook first. It defines the source-of-truth workflow for runtime state, report artifacts, and Git operations.

### MacBook

Primary development and review machine.

Use it to:

- Edit code and documentation.
- Commit and push source changes to GitHub.
- Pull generated reports from GitHub.
- Open the future lightweight Web dashboard locally.

Do not normally use the MacBook to generate or commit files under `reports/`. If `reports/` appears as untracked or modified during development, treat it as a runtime/report artifact first, not as part of a source-code change.

### Mac Mini

Primary runtime machine.

Use it to:

- Pull the latest code from GitHub.
- Run the daily sitemap check.
- Generate daily local reports.
- Commit and push generated report files back to GitHub when the report archive is enabled.

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
- `run_daily_report.py`: Runs the daily `checker.py` plus `collect_new_pages.py` flow for `mediaio`, `pincel`, `notegpt`, `imgkits`, `magichour`, `airbrush`, and `kittl`.
- `manual_sitemap_task.py`: Generates weekly browser instructions for sites that reject script sitemap fetches.
- `import_manual_sitemaps.py`: Imports browser-saved sitemap XML snapshots into `sitemaps.db`.
- `collect_new_games.py`: Legacy game-name report helper.

Runtime state and artifacts:

- `sitemaps.db`: SQLite state database. It stores first-seen URL timestamps.
- `reports/YYYY-MM-DD.md`: Daily generated Markdown report. These files are produced by the Mac Mini runtime and then pulled by MacBook for review.
- `manual_sitemaps/SITE/YYYY-MM-DD/*.xml`: Temporary browser-saved XML snapshots for weekly manual imports. These files stay local and are ignored by Git.
- `logs/`: Legacy game report output when the GitHub Actions workflow is used.

Current recommendation:

- Keep `sitemaps.db` on the Mac Mini as runtime state.
- Push `reports/` to GitHub if you want GitHub to be the report archive.
- Do not rely on Telegram or chat messages as the only long-term archive.

Git policy:

- `.gitignore` excludes local SQLite state, WAL/SHM files, Python caches, macOS noise, ad hoc logs, and browser-saved manual sitemap snapshots.
- `reports/` is intentionally not ignored so the Mac Mini can push generated daily reports to GitHub.
- Source code should normally be changed on the MacBook, then pushed to GitHub for the Mac Mini to pull.
- Runtime artifacts should normally be generated on the Mac Mini.
- During MacBook development, do not stage `reports/` unless explicitly asked. If a pull/rebase is blocked by local `reports/` files, preserve or back them up instead of deleting them blindly, then pull the canonical report files from GitHub.

## Daily Command

Run this from the project root on the Mac Mini:

```bash
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --site kittl --since-hours 24
```

This command:

- Fetches configured sitemaps for `mediaio`, `pincel`, `notegpt`, `imgkits`, `magichour`, `airbrush`, and `kittl`.
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
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --site kittl --since-hours 24
git add reports
git commit -m "Update sitemap report"
git push
```

Before committing, Hermes should check whether there are actual report changes. If there are no changes, it should skip the commit and push.

Suggested safer shell flow:

```bash
git pull
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --site imgkits --site magichour --site airbrush --site kittl --since-hours 24
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

## Weekly Manual Sitemap Workflow

Use this flow for sites that match the project goal but reject direct script sitemap fetches.

Generate the weekly browser task:

```bash
python3 manual_sitemap_task.py --site magnific --snapshot-date YYYY-MM-DD
```

Open each listed sitemap URL in a normal browser and save the XML source to the path shown by the task, for example:

```text
manual_sitemaps/magnific/YYYY-MM-DD/ai-sitemap.xml
manual_sitemaps/magnific/YYYY-MM-DD/academy-sitemap.xml
```

Import the saved snapshot into the same SQLite history:

```bash
python3 import_manual_sitemaps.py --site magnific --snapshot-date YYYY-MM-DD
```

Generate the weekly report:

```bash
python3 collect_new_pages.py --site magnific --since-hours 168 --report-dir reports/weekly
```

Commit only the generated report files when needed. Do not commit `manual_sitemaps/`; those XML files are temporary local inputs.

## Adding A New Site

Before adding a newly configured site to the default daily Mac Mini command, verify that its sitemap endpoints return XML from the Mac Mini environment. Some sites may expose sitemap URLs in `robots.txt` but return Cloudflare or other bot-protection HTML to script clients. The checker intentionally avoids storing URLs extracted from HTML error pages.

When adding a new site:

1. Confirm the site matches the project goal: it should be an SEO-focused site whose new pages can reveal keyword demand or content strategy.
2. Avoid pure directory/catalog/listing sites unless there is a clear reason their new URLs represent SEO topic expansion rather than inventory churn.
3. Check `https://example.com/robots.txt` for sitemap URLs.
4. Add a `SiteConfig` entry in `checker.py`.
5. Choose useful `include_prefixes` and `exclude_prefixes`.
6. Add keyword extraction behavior in `collect_new_pages.py` if the URL structure needs special handling.
7. Run a test with a temporary DB:

```bash
python3 checker.py --site SITE_NAME --db /private/tmp/sitemap-checker-test.db --show 5
python3 collect_new_pages.py --site SITE_NAME --db /private/tmp/sitemap-checker-test.db --since-hours 24 --stdout
```

8. Once verified, run the real baseline on the Mac Mini.

Note for `magnific`: the browser-visible sitemap index includes many Freepik-style asset inventory sitemaps. The configured monitor intentionally uses only `ai-sitemap.xml` and `academy-sitemap.xml`. `magnific` is marked `manual_weekly` because some script environments receive 403/security-filter responses even though a browser can view the XML.

## AI Agent Notes

When operating this repo:

- Prefer `python3`, not `python`.
- Do not delete or reset `sitemaps.db` unless explicitly asked. It is stateful runtime data.
- Do not overwrite reports unless the user asks for regeneration.
- Keep generated reports separate from source-code changes when possible.
- If network access fails, check DNS and outbound network access in the host environment before rerunning.
- For daily usage, prefer `run_daily_report.py` over manually chaining lower-level scripts.
