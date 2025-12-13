import argparse
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Set
from urllib.parse import unquote, urlparse


@dataclass(frozen=True)
class CollectConfig:
    name: str
    # URL path regex to capture a slug (group 1)
    slug_path_regex: re.Pattern


SITES: dict[str, CollectConfig] = {
    "crazygames": CollectConfig(
        name="crazygames",
        slug_path_regex=re.compile(r"^/game/([^/?#]+)/?$"),
    ),
    "playgama": CollectConfig(
        name="playgama",
        slug_path_regex=re.compile(r"^/game/([^/?#]+)/?$"),
    ),
}


def _utc_now_ts() -> int:
    return int(time.time())


def _utc_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema_exists(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='seen_urls'")
    if cur.fetchone() is None:
        raise RuntimeError("DB schema not found: table 'seen_urls' does not exist. Run checker.py at least once.")


def get_recent_urls(conn: sqlite3.Connection, *, site: str, since_ts: int) -> List[str]:
    cur = conn.execute(
        "SELECT url FROM seen_urls WHERE site = ? AND first_seen_ts >= ? ORDER BY first_seen_ts ASC",
        (site, since_ts),
    )
    return [row["url"] for row in cur.fetchall()]


def extract_slug(url: str, cfg: CollectConfig) -> Optional[str]:
    try:
        p = urlparse(url)
        m = cfg.slug_path_regex.match(p.path or "")
        if not m:
            return None
        return unquote(m.group(1)).strip()
    except Exception:
        return None


def normalize_game_name(slug: str) -> str:
    # Remove connector hyphens (turn into spaces for readability), then collapse whitespace.
    name = slug.replace("-", " ")
    name = re.sub(r"\s+", " ", name).strip()
    return name


def collect_names(urls: Iterable[str], cfg: CollectConfig) -> List[str]:
    names: List[str] = []
    for u in urls:
        slug = extract_slug(u, cfg)
        if not slug:
            continue
        names.append(normalize_game_name(slug))
    # Deduplicate but keep stable order
    seen: Set[str] = set()
    out: List[str] = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def append_log(log_file: str, line: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line)
        if not line.endswith("\n"):
            f.write("\n")


def append_log_lines(log_file: str, lines: Sequence[str]) -> None:
    if not lines:
        return
    with open(log_file, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
            f.write("\n")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect game names first seen within a time window, write to a log file, and print comma-joined names."
    )
    p.add_argument(
        "--site",
        action="append",
        choices=sorted(SITES.keys()),
        help="Collect for a single site (can be used multiple times). If omitted, collects all sites.",
    )
    p.add_argument("--all", action="store_true", help="Collect for all sites (default if --site is not provided).")
    p.add_argument("--db", default="sitemaps.db", help="SQLite DB path.")
    p.add_argument("--since-hours", type=float, default=24.0, help="Time window (hours) to collect first-seen URLs.")
    p.add_argument("--log-file", default="new_games_24h.log", help="Append output to this log file.")
    p.add_argument(
        "--with-site-prefix",
        action="store_true",
        help="Prefix each game name with 'site:' to avoid name collisions across sites.",
    )
    p.add_argument(
        "--stdout-csv",
        action="store_true",
        help="Force printing comma-joined names to stdout (useful for manual runs).",
    )
    p.add_argument(
        "--no-stdout",
        action="store_true",
        help="Never print to stdout (even in interactive terminal).",
    )
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()

    selected_sites: Sequence[str] = args.site or []
    if args.all or not selected_sites:
        selected_sites = list(SITES.keys())

    now_ts = _utc_now_ts()
    since_ts = now_ts - int(args.since_hours * 3600)

    conn = _connect_db(args.db)
    try:
        _ensure_schema_exists(conn)

        all_names: List[str] = []
        for site_name in selected_sites:
            cfg = SITES[site_name]
            urls = get_recent_urls(conn, site=cfg.name, since_ts=since_ts)
            names = collect_names(urls, cfg)
            if args.with_site_prefix:
                names = [f"{cfg.name}:{n}" for n in names]
            all_names.extend(names)

        # Deduplicate across sites too (while keeping order)
        seen: Set[str] = set()
        deduped: List[str] = []
        for n in all_names:
            if n in seen:
                continue
            seen.add(n)
            deduped.append(n)

        # Log format: one game per line (append).
        append_log_lines(args.log_file, deduped)

        # Only print CSV when running manually (interactive terminal), unless overridden.
        should_print = False
        if args.no_stdout:
            should_print = False
        elif args.stdout_csv:
            should_print = True
        else:
            should_print = sys.stdout.isatty()

        if should_print:
            print(",".join(deduped))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())


