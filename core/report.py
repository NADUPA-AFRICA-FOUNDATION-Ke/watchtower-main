"""Rendering sweep results. Terminal for the glance, markdown for the record."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from core.sweep import SweepResult

BANDS = [(80, "HIGH"), (60, "MED"), (30, "LOW"), (0, "WEAK")]


def band(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "WEAK"


def slug(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:limit] or "sweep"


def _short(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + "..."


def progress_line(event: dict) -> str:
    """Render a sweep progress event as a CLI line. The web UI renders the same
    events as telemetry; neither owns the format."""
    kind = event.get("type")
    if kind == "source":
        name, count = event["name"], event["count"]
        if event.get("skipped"):
            return f"  {name:<14} not searched ({event['skipped']})"
        if event.get("error"):
            # Prefer the real reason over the exception class name: "HTTP 429"
            # tells you what to do, "SourceError" does not.
            return f"  {name:<14} FAILED ({event.get('reason') or event['error']})"
        return f"  {name:<14} {count} hit(s)"
    if kind == "stage":
        stage = event["stage"]
        if stage == "dedupe":
            return f"  deduped        {event['before']} -> {event['after']}"
        if stage == "fetch":
            return f"  fetching       {event['count']} article body(ies)"
        if stage == "score":
            return f"  scoring        {event['count']} item(s) with Claude"
    if kind == "scored":
        return f"    [{event['relevance']:>3}] {event['title']}"
    return ""


# ------------------------------------------------------------- terminal

def terminal(result: SweepResult, top: int = 20) -> str:
    if not result.items:
        # "Nothing found" is a claim about the world. Only make it when every
        # source was actually searched.
        complete = getattr(result, "complete", True)
        out = [f'\nNothing found for "{result.query}".' if complete
               else f'\nINCOMPLETE SWEEP for "{result.query}" — '
                    "no results, but not every source was searched.",
               ""]
        for name, why in getattr(result, "failed", {}).items():
            out.append(f"  {name:<14} FAILED — {why}")
        for name, why in getattr(result, "skipped", {}).items():
            out.append(f"  {name:<14} not searched — {why}")
        if complete:
            out.append("Try a wider --hours window or fewer/looser terms.")
        else:
            out.append("\nDo not read this as a clean result.")
        return "\n".join(out) + "\n"

    lines = [
        "",
        f'  "{result.query}"',
        f"  {len(result.items)} result(s)"
        + (f", {len(result.strong)} strong" if result.enriched else "")
        + ("" if result.enriched else
           f"  [keyword ranking only — {getattr(result, 'scoring_error', '') or 'no API key'}]"),
        "  " + "-" * 66,
    ]

    for i, item in enumerate(result.items[:top], 1):
        lines.append(f"  {i:>2}. [{band(item.relevance):<4} {item.relevance:>3}] "
                     f"{_short(item.title, 62) or '(untitled)'}")
        meta = item.source
        if item.published_at:
            meta += f"  |  {item.published_at[:16]}"
        lines.append(f"      {meta}")
        lines.append(f"      {item.url}")
        body = item.summary or _short(item.text, 150)
        if body:
            lines.append(f"      {body}")
        lines.append("")

    if len(result.items) > top:
        lines.append(f"  ... and {len(result.items) - top} more in the report file")

    if result.entities:
        lines.append("  Recurring names:")
        lines.append("      " + ",  ".join(
            f"{name} ({n})" for name, n in result.entities[:10]))
        lines.append("")

    failed = getattr(result, "failed", {})
    skipped = getattr(result, "skipped", {})
    lines.append("  Sources: " + ",  ".join(
        f"{k} {'FAILED' if k in failed else 'skipped' if k in skipped else v}"
        for k, v in result.per_source.items()))
    for name, why in failed.items():
        lines.append(f"    ! {name}: {why}")
    for name, why in skipped.items():
        lines.append(f"    - {name} not searched: {why}")
    if failed or skipped:
        lines.append("  Coverage is incomplete — these counts are a floor, "
                     "not a finding.")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------- markdown

def markdown(result: SweepResult) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = [
        f"# Sweep: {result.query}",
        "",
        f"*{stamp} — {len(result.items)} result(s) across "
        f"{len([v for v in result.per_source.values() if v])} source(s)*",
        "",
    ]

    if not result.enriched:
        md += ["> Ranked by keyword overlap only. Set `ANTHROPIC_API_KEY` for "
               "relevance scoring, summaries and entity extraction.", ""]

    watchlist = [i for i in result.items if i.source_type == "watchlist"]
    if watchlist:
        md += ["## Watchlist matches", ""]
        for i in watchlist:
            md += [f"- **[{i.title}]({i.url})** — {i.text}"]
        md.append("")

    if result.entities:
        md += ["## Recurring names", "",
               "| Name | Mentions |", "| --- | ---: |"]
        md += [f"| {n} | {c} |" for n, c in result.entities]
        md.append("")

    md += ["## Findings", ""]
    for i, item in enumerate(result.items, 1):
        if item.source_type == "watchlist":
            continue
        md += [f"### {i}. {item.title or '(untitled)'}", "",
               f"`{band(item.relevance)} {item.relevance}` · "
               f"{item.source}"
               + (f" · {item.published_at[:16]}" if item.published_at else "")
               + (f" · {item.author}" if item.author else ""),
               "",
               f"<{item.url}>", ""]
        if item.summary:
            md += [item.summary, ""]
        elif item.text:
            md += [_short(item.text, 400), ""]
        if item.categories:
            md += ["Tags: " + ", ".join(f"`{c}`" for c in item.categories), ""]
        if item.entities:
            md += ["Entities: " + ", ".join(item.entities), ""]

    md += ["## Run detail", "",
           "| Source | Hits |", "| --- | ---: |"]
    md += [f"| {k} | {v} |" for k, v in result.per_source.items()]
    md.append("")

    if result.errors:
        md += ["### Errors", ""] + [f"- `{e}`" for e in result.errors] + [""]

    md += ["---", "",
           "Collected from public APIs and published feeds. Verify anything "
           "material against the primary source before acting on it.", ""]
    return "\n".join(md)


def save(result: SweepResult, out_dir: str | Path = "out") -> Path:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = d / f"sweep-{slug(result.query)}-{stamp}.md"
    path.write_text(markdown(result), encoding="utf-8")
    return path
