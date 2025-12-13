import argparse
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Sequence, Set, Tuple
from xml.etree import ElementTree

import requests
import urllib3
from requests.exceptions import SSLError


@dataclass(frozen=True)
class SiteConfig:
    name: str
    sitemap_url: str
    include_prefixes: Tuple[str, ...]
    # Optional extra filter hook for sites with more complex rules.
    extra_filter: Optional[Callable[[str], bool]] = None


SITES: dict[str, SiteConfig] = {
    "crazygames": SiteConfig(
        name="crazygames",
        sitemap_url="https://www.crazygames.com/en/sitemap",
        include_prefixes=("https://www.crazygames.com/game/",),
    ),
    "playgama": SiteConfig(
        name="playgama",
        # Declared in https://playgama.com/robots.txt
        sitemap_url="https://playgama.com/sitemaps/v1/sitemap-index.xml",
        include_prefixes=("https://playgama.com/game/",),
    ),
}


def _utc_now_ts() -> int:
    return int(time.time())


def _utc_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _http_get(url: str, *, timeout_s: int = 30, insecure: bool = False) -> requests.Response:
    headers = {
        "User-Agent": "sitemap-checker/1.0 (+https://example.invalid)",
        "Accept": "application/xml,text/xml,text/plain,*/*",
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout_s, verify=not insecure)
        r.raise_for_status()
        return r
    except SSLError as e:
        hint = "Try running with --insecure, or ensure your Python/OpenSSL + certs are correctly installed."
        raise RuntimeError(f"SSL error fetching {url}. {hint} Original: {e}") from e


def _looks_like_xml(content: bytes) -> bool:
    # Cheap check; avoids trying to XML-parse HTML error pages.
    head = content.lstrip()[:100].lower()
    return head.startswith(b"<?xml") or head.startswith(b"<urlset") or head.startswith(b"<sitemapindex")


def _extract_urls_regex(text: str) -> List[str]:
    url_pattern = r"https?://[^\s<>\"]+"
    return re.findall(url_pattern, text)


def _parse_sitemap_xml(xml_bytes: bytes) -> Tuple[str, List[str]]:
    """
    Returns (kind, locs) where kind is either:
    - 'urlset' for normal sitemap urlset
    - 'sitemapindex' for sitemap index
    """
    root = ElementTree.fromstring(xml_bytes)
    # Namespace-agnostic matching by stripping '{ns}' prefix.
    tag = root.tag.split("}", 1)[-1].lower()
    locs: List[str] = []
    for el in root.iter():
        el_tag = el.tag.split("}", 1)[-1].lower()
        if el_tag == "loc" and el.text:
            locs.append(el.text.strip())
    return tag, locs


def fetch_sitemap_urls(
    sitemap_url: str,
    *,
    insecure: bool = False,
    max_sitemaps: int = 200,
    max_urls: int = 500_000,
) -> List[str]:
    """
    Fetches a sitemap URL and returns all URLs found inside it.
    Supports sitemap index recursion.
    """
    print(f"Fetching sitemap: {sitemap_url}")

    r = _http_get(sitemap_url, insecure=insecure)
    content = r.content

    # Prefer XML parsing; fallback to regex extraction for non-XML endpoints.
    if not _looks_like_xml(content):
        text = r.text
        urls = _extract_urls_regex(text)
        return sorted(set(urls))

    kind, locs = _parse_sitemap_xml(content)
    if kind == "sitemapindex":
        all_urls: Set[str] = set()
        for i, child_sitemap in enumerate(locs):
            if i >= max_sitemaps:
                print(f"Reached max_sitemaps={max_sitemaps}, stopping recursion.")
                break
            child_urls = fetch_sitemap_urls(
                child_sitemap,
                insecure=insecure,
                max_sitemaps=max_sitemaps,
                max_urls=max_urls,
            )
            all_urls.update(child_urls)
            if len(all_urls) >= max_urls:
                print(f"Reached max_urls={max_urls}, stopping recursion.")
                break
        return sorted(all_urls)

    # urlset (or other): locs already are URLs
    return sorted(set(locs))


def filter_game_urls(urls: Iterable[str], site: SiteConfig) -> List[str]:
    filtered: List[str] = []
    for url in urls:
        u = url.strip()
        if not u:
            continue
        if site.include_prefixes and not any(u.startswith(p) for p in site.include_prefixes):
            continue
        if site.extra_filter and not site.extra_filter(u):
            continue
        filtered.append(u)
    return sorted(set(filtered))


def _tail(items: Sequence[str], n: int) -> Sequence[str]:
    """Return the last n items; if n <= 0, return all items."""
    if n <= 0:
        return items
    return items[-n:]


def _connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_urls (
            site TEXT NOT NULL,
            url TEXT NOT NULL,
            first_seen_ts INTEGER NOT NULL,
            first_seen_iso TEXT NOT NULL,
            PRIMARY KEY (site, url)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_urls_site_ts ON seen_urls(site, first_seen_ts);")


def _maybe_migrate_legacy(conn: sqlite3.Connection) -> None:
    """
    Legacy schema was:
      CREATE TABLE urls (timestamp TEXT, url TEXT UNIQUE)
    We migrate those rows into seen_urls as site='crazygames' if seen_urls is empty.
    """
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
    has_legacy = cur.fetchone() is not None
    if not has_legacy:
        return

    cur.execute("SELECT COUNT(1) FROM seen_urls")
    if (cur.fetchone() or [0])[0] != 0:
        return

    cur.execute("SELECT timestamp, url FROM urls")
    rows = cur.fetchall()
    if not rows:
        return

    migrated = 0
    with conn:
        for ts_str, url in rows:
            ts = _utc_now_ts()
            if isinstance(ts_str, str):
                try:
                    dt = datetime.fromisoformat(ts_str)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    ts = int(dt.timestamp())
                except Exception:
                    pass
            try:
                cur2 = conn.execute(
                    "INSERT OR IGNORE INTO seen_urls(site, url, first_seen_ts, first_seen_iso) VALUES (?, ?, ?, ?)",
                    ("crazygames", url, ts, _utc_iso(ts)),
                )
                if cur2.rowcount == 1:
                    migrated += 1
            except Exception:
                # Keep migration best-effort.
                continue

    print(f"Migrated {migrated} legacy url(s) from 'urls' into 'seen_urls' as site='crazygames'.")


def save_new_urls(
    conn: sqlite3.Connection,
    *,
    site: str,
    urls: Sequence[str],
    now_ts: int,
) -> List[str]:
    inserted: List[str] = []
    now_iso = _utc_iso(now_ts)
    with conn:
        for url in urls:
            cur = conn.execute(
                "INSERT OR IGNORE INTO seen_urls(site, url, first_seen_ts, first_seen_iso) VALUES (?, ?, ?, ?)",
                (site, url, now_ts, now_iso),
            )
            if cur.rowcount == 1:
                inserted.append(url)
    return inserted


def get_recent_urls(
    conn: sqlite3.Connection,
    *,
    site: str,
    since_ts: int,
) -> List[str]:
    cur = conn.execute(
        "SELECT url FROM seen_urls WHERE site = ? AND first_seen_ts >= ? ORDER BY first_seen_ts ASC",
        (site, since_ts),
    )
    return [row[0] for row in cur.fetchall()]


def check_site(
    conn: sqlite3.Connection,
    site: SiteConfig,
    *,
    since_hours: float,
    insecure: bool,
) -> Tuple[List[str], List[str]]:
    """
    Returns (newly_inserted_this_run, recent_within_window).
    """
    all_urls = fetch_sitemap_urls(site.sitemap_url, insecure=insecure)
    game_urls = filter_game_urls(all_urls, site)
    print(f"[{site.name}] Found {len(game_urls)} unique game URL(s) after filtering")

    now_ts = _utc_now_ts()
    new_urls = save_new_urls(conn, site=site.name, urls=game_urls, now_ts=now_ts)
    since_ts = now_ts - int(since_hours * 3600)
    recent_urls = get_recent_urls(conn, site=site.name, since_ts=since_ts)
    return new_urls, recent_urls


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Monitor game sitemaps and print newly discovered games.")
    p.add_argument(
        "--site",
        action="append",
        choices=sorted(SITES.keys()),
        help="Run checks for a single site (can be used multiple times). If omitted, runs all sites.",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Run checks for all sites (default if --site is not provided).",
    )
    p.add_argument("--db", default="sitemaps.db", help="SQLite DB path.")
    p.add_argument("--since-hours", type=float, default=24.0, help="Time window (hours) for 'recent' list.")
    p.add_argument(
        "--show",
        type=int,
        default=20,
        help="How many items to show in summaries (0 = show all).",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (use only if your environment has SSL/CA issues).",
    )
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()

    selected_sites = args.site or []
    if args.all or not selected_sites:
        selected_sites = list(SITES.keys())

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    conn = _connect_db(args.db)
    try:
        _ensure_schema(conn)
        _maybe_migrate_legacy(conn)

        print(f"\n{'='*60}")
        for site_name in selected_sites:
            site = SITES[site_name]
            print(f"\n--- Checking: {site.name} ---")
            try:
                new_urls, recent_urls = check_site(
                    conn,
                    site,
                    since_hours=args.since_hours,
                    insecure=args.insecure,
                )
            except Exception as e:
                print(f"[{site.name}] ERROR: {e}")
                continue

            if new_urls:
                print(f"[{site.name}] New game(s) discovered in THIS run: {len(new_urls)}")
                for i, url in enumerate(_tail(new_urls, args.show), 1):
                    print(f"  {i}. {url}")
            else:
                print(f"[{site.name}] No new games discovered in this run.")

            if recent_urls:
                print(f"[{site.name}] Games first seen in last {args.since_hours:g} hour(s): {len(recent_urls)}")
                for i, url in enumerate(_tail(recent_urls, args.show), 1):
                    print(f"  {i}. {url}")
            else:
                print(f"[{site.name}] No games first seen in last {args.since_hours:g} hour(s).")

        print(f"\n{'='*60}")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())