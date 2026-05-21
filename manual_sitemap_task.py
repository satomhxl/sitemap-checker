import argparse
import warnings
from datetime import datetime
from pathlib import Path
from typing import Sequence
from zoneinfo import ZoneInfo

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

from checker import SITES, manual_weekly_site_names


def build_task(
    *,
    selected_sites: Sequence[str],
    snapshot_date: str,
    input_dir: str,
    generated_at: datetime,
) -> str:
    lines = [
        f"# Manual Sitemap Task - {snapshot_date}",
        "",
        f"Generated at: {generated_at.isoformat()}",
        "",
        "Open each sitemap URL in a browser, save the XML source into the listed path, then run the import command.",
        "",
    ]

    for site_name in selected_sites:
        site = SITES[site_name]
        site_dir = Path(input_dir) / site.name / snapshot_date
        lines.append(f"## {site.name}")
        lines.append("")
        for i, sitemap_url in enumerate(site.sitemap_urls, 1):
            filename = Path(sitemap_url.rstrip("/")).name or f"sitemap-{i}.xml"
            save_path = site_dir / filename
            lines.append(f"{i}. {sitemap_url}")
            lines.append(f"   Save as: `{save_path}`")
        lines.append("")
        lines.append("Import command:")
        lines.append("")
        lines.append("```bash")
        lines.append(
            f"python3 import_manual_sitemaps.py --site {site.name} "
            f"--snapshot-date {snapshot_date} --input-dir {input_dir}"
        )
        lines.append("```")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate weekly manual sitemap collection instructions.")
    p.add_argument(
        "--site",
        action="append",
        choices=sorted(manual_weekly_site_names()),
        help="Manual weekly site to include. If omitted, includes all manual weekly sites.",
    )
    p.add_argument("--snapshot-date", help="Snapshot date in YYYY-MM-DD. Defaults to today in --timezone.")
    p.add_argument("--timezone", default="Asia/Shanghai", help="Timezone used for the default snapshot date.")
    p.add_argument("--input-dir", default="manual_sitemaps", help="Directory where manually saved XML files go.")
    p.add_argument("--output", help="Optional Markdown file path. If omitted, prints only to stdout.")
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()
    generated_at = datetime.now(ZoneInfo(args.timezone))
    snapshot_date = args.snapshot_date or f"{generated_at:%Y-%m-%d}"
    selected_sites = args.site or manual_weekly_site_names()

    task = build_task(
        selected_sites=selected_sites,
        snapshot_date=snapshot_date,
        input_dir=args.input_dir,
        generated_at=generated_at,
    )
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(task, encoding="utf-8")
        print(f"Wrote manual sitemap task: {output}")
    else:
        print(task, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
