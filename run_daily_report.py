import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


DEFAULT_SITES = ("mediaio", "pincel", "notegpt", "imgkits", "magichour", "airbrush", "kittl")
MANUAL_WEEKLY_SITES = ("magnific",)


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Update sitemap DB and generate a dated local report.")
    p.add_argument("--db", default="sitemaps.db", help="SQLite DB path.")
    p.add_argument("--since-hours", type=float, default=24.0, help="Time window for first-seen URLs.")
    p.add_argument("--timezone", default="Asia/Shanghai", help="Timezone for report filenames.")
    p.add_argument("--report-dir", default="reports", help="Directory where dated Markdown reports are written.")
    p.add_argument(
        "--site",
        action="append",
        choices=(
            "crazygames",
            "playgama",
            "gamedistribution",
            "gamemonetize",
            "mediaio",
            "pincel",
            "notegpt",
            "imgkits",
            "magichour",
            "airbrush",
            "kittl",
            "magnific",
        ),
        help="Site to check and report. Defaults to mediaio, pincel, notegpt, imgkits, magichour, airbrush, and kittl.",
    )
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()
    sites = args.site or list(DEFAULT_SITES)
    manual_sites = [site for site in sites if site in MANUAL_WEEKLY_SITES]
    if manual_sites:
        print(
            "Skipping manual weekly site(s) in daily report flow: "
            + ", ".join(manual_sites)
            + ". Use manual_sitemap_task.py and import_manual_sitemaps.py instead."
        )
        sites = [site for site in sites if site not in MANUAL_WEEKLY_SITES]
    if not sites:
        print("No automatic sites selected.")
        return 0

    checker_cmd = [sys.executable, "checker.py", "--db", args.db, "--show", "5"]
    report_cmd = [
        sys.executable,
        "collect_new_pages.py",
        "--db",
        args.db,
        "--since-hours",
        str(args.since_hours),
        "--timezone",
        args.timezone,
        "--report-dir",
        args.report_dir,
    ]
    for site in sites:
        checker_cmd.extend(["--site", site])
        report_cmd.extend(["--site", site])

    subprocess.run(checker_cmd, check=True)
    generated_at = datetime.now(ZoneInfo(args.timezone))
    report_path = Path(args.report_dir) / f"{generated_at:%Y-%m-%d}.md"
    subprocess.run(report_cmd, check=True)
    print(f"Daily sitemap report ready: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
