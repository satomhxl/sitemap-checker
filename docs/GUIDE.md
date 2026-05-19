# Setup Guide: MacBook + Mac Mini + Hermes

This guide explains how to take the current local project and make the intended workflow actually run end to end.

The target workflow is:

```text
MacBook develops and pushes code
  -> GitHub stores source code
Mac Mini pulls code and runs the monitor
  -> Hermes triggers the daily job
  -> reports are generated locally
  -> reports are optionally pushed to GitHub
MacBook pulls or receives the result
  -> user reviews the report or dashboard
```

## Phase 1: Finish The MacBook Development Copy

On the MacBook, first decide what should be committed as source code.

Recommended source files to commit:

- `checker.py`
- `collect_new_pages.py`
- `run_daily_report.py`
- `collect_new_games.py` if you want to keep the current legacy game changes
- `.github/workflows/sitemap-checker.yml` if you want the workflow tweaks
- `README.md`
- `docs/GUIDE.md`
- `docs/RUNBOOK.md`

Usually do not commit local runtime files from the MacBook:

- `sitemaps.db`
- `sitemaps.db-shm`
- `sitemaps.db-wal`
- `tmp_games.log`
- `new_games_24h.log`

These are listed in `.gitignore` so they do not accidentally get staged.

For reports, choose one policy:

- Commit `reports/` if GitHub should be the report archive.
- Do not commit `reports/` if reports should stay only on the Mac Mini or be sent by Telegram.

Recommended first policy: commit `reports/` later from the Mac Mini, not from the MacBook development copy. `reports/` is intentionally not ignored so the Mac Mini can push daily reports when that workflow is enabled.

Then commit and push code:

```bash
git status --short
git add checker.py collect_new_pages.py run_daily_report.py README.md docs
git add .github/workflows/sitemap-checker.yml collect_new_games.py
git commit -m "Add sitemap report workflow"
git push
```

If you do not want to include the GitHub Actions or legacy game changes, omit those files from `git add`.

## Phase 2: Prepare The Mac Mini Runtime Copy

On the Mac Mini, clone or update the repo:

```bash
git clone YOUR_GITHUB_REPO_URL sitemap-checker
cd sitemap-checker
```

If the repo already exists:

```bash
cd /path/to/sitemap-checker
git pull
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

If macOS complains about Python certificates or package installation, fix Python/pip first before wiring Hermes. The monitor should be boring and repeatable before automation touches it.

## Phase 3: Run The First Baseline On Mac Mini

Run the daily command manually once:

```bash
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --since-hours 24
```

Expected behavior:

- `mediaio` fetches multiple `media.io` sitemap files.
- `pincel` fetches `https://pincel.app/sitemap.xml`.
- `notegpt` fetches `https://notegpt.io/sitemap.xml` and `https://notegpt.io/sitemap_chatgpt.xml`.
- `sitemaps.db` is created or updated.
- `reports/YYYY-MM-DD.md` is created.

Important baseline note:

- The first real Mac Mini run may include many existing pages if `sitemaps.db` does not already contain a baseline.
- That is normal.
- After the baseline is established, future daily reports should contain only pages first seen in the previous 24 hours.

If you want to avoid pushing a huge baseline report, delete or ignore the first generated report after confirming the DB was seeded.

## Phase 4: Decide What Mac Mini Pushes Back

Recommended lightweight sync:

- Mac Mini keeps `sitemaps.db` local.
- Mac Mini pushes only `reports/`.

Reason:

- `sitemaps.db` is runtime state and changes often.
- `reports/` is human-readable and works well as a GitHub archive.

If you want the dashboard to work from GitHub later, add a JSON export such as:

```text
public/data/events.json
```

That is a future enhancement. The current project already supports Markdown reports.

Recommended sync rules:

- Source code changes are made on the MacBook and pushed to GitHub.
- Runtime state stays on the Mac Mini and is ignored by Git.
- Daily human-readable artifacts can be pushed from the Mac Mini.
- Telegram is for notification, not the source of truth.

Current `.gitignore` policy:

- Ignored: SQLite runtime files, local logs, Python caches, macOS noise.
- Not ignored: source code, docs, `reports/`.

## Phase 5: Create A Hermes Task

In Hermes, create a daily task that runs on the Mac Mini from the project directory.

Use this command flow:

```bash
cd /path/to/sitemap-checker
git pull
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --since-hours 24
git add reports
if ! git diff --cached --quiet; then
  git commit -m "Update sitemap report"
  git push
fi
```

Suggested Hermes instruction:

```text
Every day, open the sitemap-checker project on this Mac Mini. Pull the latest code, run `python3 run_daily_report.py --site mediaio --site pincel --site notegpt --since-hours 24`, then commit and push changed files under `reports/` only if there are actual changes. If the command fails, send me the error summary in Telegram. Do not delete `sitemaps.db`.
```

If Telegram is already connected, use Telegram for status messages:

- Success: send a short message with the report filename and count summary.
- Failure: send the command that failed and the relevant error.

Do not send the entire report through Telegram unless the report is small. Use GitHub as the archive.

## Phase 6: Verify The Full Loop

Run Hermes manually once before relying on the schedule.

Check on the Mac Mini:

```bash
git status --short
ls reports
```

Check on GitHub:

- A new commit appears if `reports/` changed.
- The new report file is visible under `reports/`.

Check on the MacBook:

```bash
git pull
ls reports
```

Open the latest Markdown report locally.

At this point, the basic workflow is live.

## Phase 7: Add The Lightweight Dashboard Later

The dashboard should be a static local Web page.

Recommended first dashboard deliverables:

- `dashboard.html`
- `public/data/events.json`
- An exporter command that writes JSON after each daily run

The daily flow would then become:

```bash
python3 run_daily_report.py --site mediaio --site pincel --site notegpt --since-hours 24
python3 export_events.py --site mediaio --site pincel --site notegpt --output public/data/events.json
```

Then the MacBook can review:

```bash
python3 -m http.server 8080
```

Open:

```text
http://localhost:8080/dashboard.html
```

Do not build Electron, Tauri, or a backend API for the first version. Static Web plus JSON is enough.

## Troubleshooting

### Python command not found

Use `python3`, not `python`.

### Network fetch fails

Run this manually on the Mac Mini:

```bash
python3 checker.py --site mediaio --site pincel --site notegpt --show 5
```

If it fails, confirm DNS, network access, and Python SSL/certificate behavior.

### Hermes commits nothing

That can be normal if the report did not change. Check:

```bash
git status --short
```

### The first report is huge

That usually means the Mac Mini just created its baseline. Keep the DB, and future reports should be smaller.

### Reports are generated but not visible on MacBook

Confirm the Mac Mini pushed:

```bash
git log --oneline -5
git status --short
```

Then pull on the MacBook:

```bash
git pull
```
