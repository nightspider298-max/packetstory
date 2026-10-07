"""Standalone HTML reporting for PacketStory."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .models import CaptureAnalysis


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_e(v)}</td>" for v in row) + "</tr>" for row in rows)
    if not rows:
        body = f'<tr><td colspan="{len(headers)}" class="empty">No activity observed.</td></tr>'
    return f"<div class=table-wrap><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def render_html(analysis: CaptureAnalysis) -> str:
    """Render an offline HTML report with all captured values escaped."""
    s = analysis.statistics
    timeline = _table(
        ["Time", "Event", "Details", "Source", "Destination"],
        [[e.timestamp, e.kind, e.summary, e.source, e.destination] for e in analysis.timeline],
    )
    conversations = _table(
        ["Protocol", "Source", "Destination", "Packets", "Bytes", "SYN attempts"],
        [
            [
                c.protocol,
                f"{c.source}:{c.source_port or ''}",
                f"{c.destination}:{c.destination_port or ''}",
                c.packets,
                c.bytes,
                c.syn_attempts,
            ]
            for c in analysis.conversations[:100]
        ],
    )
    dns = _table(
        ["Time", "Query", "Type", "Answers"],
        [
            [
                r["timestamp"],
                r["query"],
                "Response" if r["response"] else "Query",
                ", ".join(r["answers"]),
            ]
            for r in analysis.dns
        ],
    )
    http = _table(
        ["Time", "Source", "Method / Status", "Host", "Path", "User-Agent"],
        [
            [
                r["timestamp"],
                f"{r.get('source')}:{r.get('source_port')}",
                r.get("method", r.get("status", "")),
                r.get("host", ""),
                r.get("path", ""),
                r.get("user_agent", ""),
            ]
            for r in analysis.http
        ],
    )
    tls = _table(
        ["Time", "Source", "Destination", "SNI"],
        [[r["timestamp"], r["source"], r["destination"], r["server_name"]] for r in analysis.tls],
    )
    indicators = _table(
        ["Type", "Value", "Label", "Reason", "First seen"],
        [[i.kind, i.value, i.label, i.reason, i.first_seen] for i in analysis.indicators],
    )
    protocols = _table(
        ["Protocol", "Packets"], [[k, v] for k, v in s["protocol_distribution"].items()]
    )
    top_talkers = _table(
        ["Address", "Packets"], [[r["address"], r["packets"]] for r in s["top_talkers"]]
    )
    findings = (
        "".join(
            f'<div class="finding"><strong>{_e(f["severity"])} · {_e(f["title"])}</strong><p>{_e(f["reason"])}</p></div>'
            for f in analysis.findings
        )
        or '<p class="empty">No contextual findings generated.</p>'
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PacketStory — {_e(analysis.capture["file_name"])}</title>
<style>
:root{{--bg:#08111f;--panel:#101d30;--line:#243750;--text:#e8f0fa;--muted:#9db1c9;--blue:#54b4ff;--cyan:#7ce4df}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 10% 0%,#142744,var(--bg) 42%);color:var(--text);font:15px/1.55 system-ui,Segoe UI,sans-serif}}main{{max-width:1250px;margin:auto;padding:36px 24px 80px}}header{{border-bottom:1px solid var(--line);padding:22px 0 30px}}.eyebrow{{color:var(--cyan);text-transform:uppercase;letter-spacing:.16em;font-size:12px}}h1{{margin:.15em 0;font-size:clamp(30px,5vw,48px)}}h2{{margin:34px 0 12px;font-size:21px}}p,.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0}}.card,section{{background:var(--panel);border:1px solid var(--line);border-radius:12px}}.card{{padding:16px}}.card b{{display:block;font-size:25px;color:var(--blue)}}.card span{{color:var(--muted);font-size:13px}}section{{padding:4px 18px 18px;margin:12px 0}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:9px 10px;max-width:420px;overflow-wrap:anywhere}}th{{color:var(--cyan);font-weight:600}}tr:last-child td{{border-bottom:0}}.empty{{color:var(--muted);font-style:italic}}.finding{{border-left:3px solid var(--blue);padding:2px 14px;margin:12px 0;background:#0c1829}}footer{{margin-top:36px;color:var(--muted);font-size:12px}}a{{color:var(--cyan)}}
</style></head><body><main><header><div class="eyebrow">Network forensics · offline report</div><h1>PacketStory</h1><p>Investigation timeline for <strong>{_e(analysis.capture["file_name"])}</strong></p></header>
<h2>Executive Summary</h2><p>This report summarizes observable packet metadata. It does not decrypt encrypted traffic or determine intent; contextual findings require analyst review.</p><div class="cards"><div class="card"><b>{s["total_packets"]:,}</b><span>Packets</span></div><div class="card"><b>{s["capture_duration_seconds"]:.3f}s</b><span>Capture duration</span></div><div class="card"><b>{len(analysis.conversations):,}</b><span>Bidirectional conversations</span></div><div class="card"><b>{len(analysis.indicators):,}</b><span>Indicators</span></div></div>
<h2>Capture Information</h2><section><p>Format: {_e(analysis.capture["format"])} · Size: {analysis.capture["file_size_bytes"]:,} bytes<br>First packet: {_e(analysis.capture["first_packet"])}<br>Last packet: {_e(analysis.capture["last_packet"])}</p></section>
<h2>Key Findings</h2><section>{findings}</section><h2>Investigation Timeline</h2><section>{timeline}</section><h2>Network Conversations</h2><section>{conversations}</section><h2>DNS Activity</h2><section>{dns}</section><h2>HTTP Activity</h2><section>{http}</section><h2>TLS Activity</h2><section>{tls}</section><h2>Indicators</h2><p>“Observed” means present in capture metadata. “Interesting” is a review cue, not a maliciousness verdict.</p><section>{indicators}</section>
<h2>Statistics</h2><section><p>Approximate transferred bytes: {s["approx_transferred_bytes"]:,} · Captured bytes: {s["captured_bytes"]:,} · DNS queries: {s["dns_query_count"]} · HTTP requests: {s["http_request_count"]} · TCP SYN attempts: {s["tcp_connection_attempts"]} · Parse errors: {s["parse_errors"]}</p><h3>Protocol Distribution</h3>{protocols}<h3>Top Talkers</h3>{top_talkers}</section><h2>Analyst Notes</h2><section><p>Add case-specific context, scope, time zone, and corroborating evidence in your case management process.</p></section><h2>Limitations</h2><section><ul><li>Encrypted payloads are not decrypted; TLS output is limited to visible handshake metadata.</li><li>HTTP extraction covers visible HTTP/1 headers and start lines. Fragmented or non-standard streams may be incomplete.</li><li>Conversation byte totals sum packet lengths from both directions and can include retransmissions.</li><li>Absence of an indicator in this report does not establish that traffic was benign.</li></ul></section><footer>Generated locally by PacketStory v0.1.0 · No capture data was uploaded.</footer></main></body></html>"""


def write_html(analysis: CaptureAnalysis, destination: str | Path) -> Path:
    """Write a standalone HTML report and return its path."""
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(analysis), encoding="utf-8")
    return output


def write_json(analysis: CaptureAnalysis, destination: str | Path) -> Path:
    """Write machine-readable analysis data."""
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(analysis.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return output
