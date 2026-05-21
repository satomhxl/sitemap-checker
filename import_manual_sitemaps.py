import argparse
import sqlite3
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence, Set

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

from checker import (
    SITES,
    _connect_db,
    _ensure_schema,
    _looks_like_html,
    _looks_like_xml,
    _parse_sitemap_xml,
    filter_site_urls,
    manual_weekly_site_names,
    save_new_urls,
)


def _utc_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _extract_urls_from_files(files: Sequence[Path]) -> List[str]:
    urls: Set[str] = set()
    for path in files:
        content = path.read_bytes()
        if not _looks_like_xml(content):
            if _looks_like_html(content):
                raise RuntimeError(f"{path} looks like HTML, not sitemap XML.")
            raise RuntimeError(f"{path} does not look like sitemap XML.")
        kind, locs = _parse_sitemap_xml(content)
        if kind not in {"urlset", "sitemapindex"}:
            raise RuntimeError(f"{path} has unexpected sitemap root: {kind}")
        urls.update(locs)
    return sorted(urls)


def _snapshot_files(input_dir: str, site_name: str, snapshot_date: str) -> List[Path]:
    snapshot_dir = Path(input_dir) / site_name / snapshot_date
    if not snapshot_dir.exists():
        raise RuntimeError(f"Manual sitemap snapshot directory not found: {snapshot_dir}")
    files = sorted(path for path in snapshot_dir.iterdir() if path.is_file() and path.suffix.lower() == ".xml")
    if not files:
        raise RuntimeError(f"No .xml files found in {snapshot_dir}")
    return files


def import_snapshot(
    *,
    conn: sqlite3.Connection,
    site_name: str,
    snapshot_date: str,
    input_dir: str,
    import_ts: int,
) -> List[str]:
    site = SITES[site_name]
    files = _snapshot_files(input_dir, site.name, snapshot_date)
    raw_urls = _extract_urls_from_files(files)
    site_urls = filter_site_urls(raw_urls, site)
    print(f"[{site.name}] Loaded {len(files)} XML file(s) from {Path(input_dir) / site.name / snapshot_date}")
    print(f"[{site.name}] Found {len(site_urls)} unique URL(s) after filtering")
    return save_new_urls(conn, site=site.name, urls=site_urls, now_ts=import_ts)


def _tail(items: Sequence[str], n: int) -> Sequence[str]:
    if n <= 0:
        return items
    return items[-n:]


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Import manually saved sitemap XML snapshots into the sitemap DB.")
    p.add_argument(
        "--site",
        action="append",
        choices=sorted(manual_weekly_site_names()),
        help="Manual weekly site to import. If omitted, imports all manual weekly sites.",
    )
    p.add_argument("--snapshot-date", required=True, help="Snapshot date in YYYY-MM-DD.")
    p.add_argument("--input-dir", default="manual_sitemaps", help="Directory containing manually saved XML files.")
    p.add_argument("--db", default="sitemaps.db", help="SQLite DB path.")
    p.add_argument("--show", type=int, default=20, help="How many newly inserted URLs to show (0 = show all).")
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()
    selected_sites = args.site or manual_weekly_site_names()
    import_ts = int(time.time())

    conn = _connect_db(args.db)
    try:
        _ensure_schema(conn)
        for site_name in selected_sites:
            print(f"\n--- Importing manual sitemap snapshot: {site_name} ({args.snapshot_date}) ---")
            new_urls = import_snapshot(
                conn=conn,
                site_name=site_name,
                snapshot_date=args.snapshot_date,
                input_dir=args.input_dir,
                import_ts=import_ts,
            )
            if new_urls:
                print(f"[{site_name}] New URL(s) imported at {_utc_iso(import_ts)}: {len(new_urls)}")
                for i, url in enumerate(_tail(new_urls, args.show), 1):
                    print(f"  {i}. {url}")
            else:
                print(f"[{site_name}] No new URLs in this manual snapshot.")
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
