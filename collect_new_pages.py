import argparse
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlparse
from zoneinfo import ZoneInfo


UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CollectConfig:
    name: str
    drop_prefix_segments: Sequence[str] = ()
    locale_segments: Sequence[str] = ()


SITES: dict[str, CollectConfig] = {
    "crazygames": CollectConfig(name="crazygames", drop_prefix_segments=("game",)),
    "playgama": CollectConfig(name="playgama", drop_prefix_segments=("game",)),
    "gamedistribution": CollectConfig(name="gamedistribution", drop_prefix_segments=("games",)),
    "gamemonetize": CollectConfig(name="gamemonetize"),
    "mediaio": CollectConfig(
        name="mediaio",
        locale_segments=("br", "de", "es", "fr", "id", "it", "jp", "ko"),
    ),
    "pincel": CollectConfig(name="pincel"),
    "notegpt": CollectConfig(
        name="notegpt",
        drop_prefix_segments=("blog", "chatgpt", "ai-models"),
        locale_segments=("cn", "de", "es", "fr", "id", "ja", "jp", "ko", "pt", "ru", "zh-TW"),
    ),
    "appbrain": CollectConfig(name="appbrain"),
}


def _now_ts() -> int:
    return int(time.time())


def _connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema_exists(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='seen_urls'")
    if cur.fetchone() is None:
        raise RuntimeError("DB schema not found: table 'seen_urls' does not exist. Run checker.py at least once.")


def get_recent_rows(conn: sqlite3.Connection, *, site: str, since_ts: int) -> List[sqlite3.Row]:
    cur = conn.execute(
        """
        SELECT url, first_seen_iso
        FROM seen_urls
        WHERE site = ? AND first_seen_ts >= ?
        ORDER BY first_seen_ts ASC, url ASC
        """,
        (site, since_ts),
    )
    return cur.fetchall()


def _path_segments(url: str, cfg: CollectConfig) -> List[str]:
    p = urlparse(url)
    segments = [unquote(part) for part in (p.path or "").split("/") if part]
    if segments and segments[0] in cfg.locale_segments:
        segments = segments[1:]
    while segments and segments[0] in cfg.drop_prefix_segments:
        segments = segments[1:]
    if segments and UUID_RE.match(segments[-1]):
        segments = segments[:-1]
    return segments


def _canonical_slug(url: str, cfg: CollectConfig) -> Tuple[str, ...]:
    return tuple(_path_segments(url, cfg))


def get_historical_canonical_slugs(
    conn: sqlite3.Connection,
    *,
    site: str,
    cfg: CollectConfig,
    before_ts: int,
) -> Set[Tuple[str, ...]]:
    cur = conn.execute(
        """
        SELECT url
        FROM seen_urls
        WHERE site = ? AND first_seen_ts < ?
        """,
        (site, before_ts),
    )
    return {_canonical_slug(row["url"], cfg) for row in cur.fetchall()}


def keyword_from_url(url: str, cfg: CollectConfig) -> Optional[str]:
    try:
        segments = _path_segments(url, cfg)
        if not segments:
            return None

        if cfg.name == "pincel":
            if segments[0] == "media" and len(segments) >= 2:
                raw = segments[1]
            elif segments[0] in {"tools", "free"}:
                raw = " ".join(segments[1:] or segments[:1])
            else:
                raw = segments[-1]
        elif cfg.name == "appbrain" and segments[0] == "app" and len(segments) >= 2:
            raw = segments[1]
        elif cfg.name == "gamemonetize":
            raw = re.sub(r"-game$", "", segments[-1])
        else:
            raw = segments[-1]

        raw = re.sub(r"\.(html?|php)$", "", raw, flags=re.IGNORECASE)
        keyword = re.sub(r"[-_]+", " ", raw)
        keyword = re.sub(r"\s+", " ", keyword).strip()
        return keyword or None
    except Exception:
        return None


def _dedupe_items(items: Iterable[tuple[str, str, str]]) -> List[tuple[str, str, str]]:
    seen: Set[tuple[str, str]] = set()
    out: List[tuple[str, str, str]] = []
    for keyword, url, first_seen in items:
        key = (keyword.lower(), url)
        if key in seen:
            continue
        seen.add(key)
        out.append((keyword, url, first_seen))
    return out


def build_report(
    *,
    conn: sqlite3.Connection,
    selected_sites: Sequence[str],
    since_ts: int,
    generated_at: datetime,
) -> str:
    lines: List[str] = [
        f"# Sitemap New Page Report - {generated_at:%Y-%m-%d}",
        "",
        f"Generated at: {generated_at.isoformat()}",
        "",
    ]

    total = 0
    for site_name in selected_sites:
        cfg = SITES[site_name]
        rows = get_recent_rows(conn, site=cfg.name, since_ts=since_ts)
        historical_canonical_slugs: Set[Tuple[str, ...]] = set()
        if cfg.locale_segments and rows:
            historical_canonical_slugs = get_historical_canonical_slugs(
                conn,
                site=cfg.name,
                cfg=cfg,
                before_ts=since_ts,
            )

        items = []
        locale_variant_count = 0
        for row in rows:
            keyword = keyword_from_url(row["url"], cfg)
            if not keyword:
                continue
            if historical_canonical_slugs and _canonical_slug(row["url"], cfg) in historical_canonical_slugs:
                locale_variant_count += 1
                continue
            items.append((keyword, row["url"], row["first_seen_iso"]))
        items = _dedupe_items(items)
        total += len(items)

        if cfg.locale_segments:
            lines.append(f"## {cfg.name} ({len(items)} new pages + {locale_variant_count} locale variants)")
        else:
            lines.append(f"## {cfg.name} ({len(items)})")
        if not items:
            lines.append("")
            lines.append("No new pages in this window.")
            if locale_variant_count:
                lines.append("")
                lines.append(f"*... and {locale_variant_count} more locale variants of existing pages*")
            lines.append("")
            continue

        lines.append("")
        lines.append("| Keyword candidate | URL | First seen |")
        lines.append("| --- | --- | --- |")
        for keyword, url, first_seen in items:
            safe_keyword = keyword.replace("|", "\\|")
            lines.append(f"| {safe_keyword} | {url} | {first_seen} |")
        if locale_variant_count:
            lines.append("")
            lines.append(f"*... and {locale_variant_count} more locale variants of existing pages*")
        lines.append("")

    lines.insert(4, f"Total keyword candidates: {total}")
    lines.insert(5, "")
    return "\n".join(lines).rstrip() + "\n"


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate a local report of newly discovered sitemap pages.")
    p.add_argument(
        "--site",
        action="append",
        choices=sorted(SITES.keys()),
        help="Collect for a single site (can be used multiple times). If omitted, collects all sites.",
    )
    p.add_argument("--all", action="store_true", help="Collect for all sites (default if --site is not provided).")
    p.add_argument("--db", default="sitemaps.db", help="SQLite DB path.")
    p.add_argument("--since-hours", type=float, default=24.0, help="Time window (hours) to collect first-seen URLs.")
    p.add_argument("--timezone", default="Asia/Shanghai", help="Timezone for report filenames and timestamps.")
    p.add_argument("--report-dir", default="reports", help="Directory where dated Markdown reports are written.")
    p.add_argument("--output", help="Explicit report file path. Defaults to reports/YYYY-MM-DD.md.")
    p.add_argument("--stdout", action="store_true", help="Also print the report to stdout.")
    return p


def main() -> int:
    args = _build_arg_parser().parse_args()
    selected_sites: Sequence[str] = args.site or []
    if args.all or not selected_sites:
        selected_sites = list(SITES.keys())

    now_ts = _now_ts()
    since_ts = now_ts - int(args.since_hours * 3600)
    generated_at = datetime.fromtimestamp(now_ts, tz=ZoneInfo(args.timezone))

    conn = _connect_db(args.db)
    try:
        _ensure_schema_exists(conn)
        report = build_report(
            conn=conn,
            selected_sites=selected_sites,
            since_ts=since_ts,
            generated_at=generated_at,
        )
    finally:
        conn.close()

    output = Path(args.output) if args.output else Path(args.report_dir) / f"{generated_at:%Y-%m-%d}.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    if args.stdout or sys.stdout.isatty():
        print(report, end="")
    print(f"Wrote report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
