"""PCAP/PCAPNG ingestion and protocol metadata extraction using Scapy."""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any

_scapy_loading_logger = logging.getLogger("scapy.loading")
_scapy_loading_level = _scapy_loading_logger.level
_scapy_loading_logger.setLevel(logging.ERROR)
try:
    from scapy.layers.dns import DNS, DNSQR  # type: ignore[import-untyped]
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore[import-untyped]
    from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
    from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
    from scapy.utils import PcapReader  # type: ignore[import-untyped]
finally:
    _scapy_loading_logger.setLevel(_scapy_loading_level)
del _scapy_loading_level, _scapy_loading_logger

from .models import (  # noqa: E402 - Scapy is loaded with its startup warning suppressed above.
    CaptureAnalysis,
    Conversation,
    Indicator,
    TimelineEvent,
    iso_timestamp,
)

_LOGGER = logging.getLogger(__name__)

COMMON_PORTS = {
    20,
    21,
    22,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    443,
    465,
    587,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    8080,
    8443,
}
MAX_PACKETS = 2_000_000


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".\x00")
    return str(value).rstrip(".")


def _add_indicator(
    items: dict[tuple[str, str], Indicator],
    value: str,
    kind: str,
    ts: str,
    label: str = "Observed",
    reason: str = "Observed directly in packet metadata.",
) -> None:
    key = (kind, value)
    if key not in items:
        items[key] = Indicator(value=value, kind=kind, label=label, reason=reason, first_seen=ts)


def _http_metadata(payload: bytes) -> dict[str, str] | None:
    """Parse only visible HTTP/1 start lines and headers; never decode bodies."""
    try:
        lines = payload[:16384].decode("iso-8859-1", errors="replace").split("\r\n")
    except Exception:
        return None
    if not lines:
        return None
    request = re.match(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/", lines[0], re.I
    )
    response = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0], re.I)
    if not request and not response:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()[:2048]
    result: dict[str, str] = {}
    if request:
        result.update(method=request.group(1).upper(), path=request.group(2)[:2048])
    if response:
        result["status"] = response.group(1)
    for header in ("host", "user-agent"):
        if header in headers:
            result[header.replace("-", "_")] = headers[header]
    return result


def _extract_tls_sni(payload: bytes) -> str | None:
    """Extract a DNS-name SNI from a complete, visible TLS ClientHello record."""
    if len(payload) < 9 or payload[0] != 22:
        return None
    record_end = 5 + int.from_bytes(payload[3:5], "big")
    if record_end > len(payload):
        return None
    record = payload[5:record_end]
    if not record or record[0] != 1:
        return None
    handshake_end = 4 + int.from_bytes(record[1:4], "big")
    if handshake_end > len(record):
        return None
    hello = record[4:handshake_end]
    offset = 34  # legacy_version and 32-byte client random
    if len(hello) <= offset:
        return None
    offset += 1 + hello[offset]  # legacy session id
    if len(hello) < offset + 2:
        return None
    cipher_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2 + cipher_length
    if len(hello) <= offset:
        return None
    compression_length = hello[offset]
    offset += 1 + compression_length
    if len(hello) < offset + 2:
        return None
    extensions_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2
    extension_end = min(len(hello), offset + extensions_length)
    while offset + 4 <= extension_end:
        extension_type = int.from_bytes(hello[offset : offset + 2], "big")
        extension_length = int.from_bytes(hello[offset + 2 : offset + 4], "big")
        offset += 4
        end = offset + extension_length
        if end > extension_end:
            return None
        if extension_type == 0 and extension_length >= 5:
            names = hello[offset:end]
            name_end = min(len(names), 2 + int.from_bytes(names[:2], "big"))
            index = 2
            while index + 3 <= name_end:
                name_type = names[index]
                name_length = int.from_bytes(names[index + 1 : index + 3], "big")
                index += 3
                if index + name_length > name_end:
                    return None
                if name_type == 0:
                    try:
                        value = names[index : index + name_length].decode("ascii")
                    except UnicodeDecodeError:
                        return None
                    if value and len(value) <= 253 and not any(ord(c) < 33 for c in value):
                        return value.lower()
                    return None
                index += name_length
        offset = end
    return None


def _tls_sni(packet: Any) -> str | None:
    if not packet.haslayer(TCP):
        return None
    return _extract_tls_sni(bytes(packet[TCP].payload))


def _conversation_key(
    source: str | None,
    destination: str | None,
    source_port: int,
    destination_port: int,
    protocol: str,
) -> tuple[str, int, str, int, str]:
    left = (source or "?", source_port)
    right = (destination or "?", destination_port)
    if left <= right:
        return left[0], left[1], right[0], right[1], protocol
    return right[0], right[1], left[0], left[1], protocol


def analyze_capture(path: str | Path, *, max_packets: int = MAX_PACKETS) -> CaptureAnalysis:
    """Read a PCAP or PCAPNG capture and summarize observable metadata.

    Captures are treated as untrusted input and packet processing is bounded by
    ``max_packets``. Payload inspection is limited to visible HTTP headers.
    """
    capture_path = Path(path)
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")
    if max_packets < 1:
        raise ValueError("max_packets must be positive")
    _LOGGER.info("Starting offline packet analysis")
    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    conversation_map: dict[tuple[str, int, str, int, str], Conversation] = {}
    events: list[TimelineEvent] = []
    dns_records: list[dict[str, Any]] = []
    http_records: list[dict[str, Any]] = []
    tls_records: list[dict[str, Any]] = []
    indicators: dict[tuple[str, str], Indicator] = {}
    start: float | None = None
    end: float | None = None
    total_bytes = 0
    count = 0
    errors = 0

    try:
        reader = PcapReader(str(capture_path))
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(
            f"Unable to read capture (invalid PCAP/PCAPNG or unsupported link type): {exc}"
        ) from exc
    try:
        for packet in reader:
            count += 1
            if count > max_packets:
                raise ValueError(f"Capture exceeds the configured packet limit ({max_packets:,}).")
            try:
                ts_epoch = float(packet.time)
                ts = iso_timestamp(ts_epoch)
                start = ts_epoch if start is None else min(start, ts_epoch)
                end = ts_epoch if end is None else max(end, ts_epoch)
                size = len(packet)
                total_bytes += size
                if packet.haslayer(Ether):
                    protocols["Ethernet"] += 1

                src = dst = None
                if packet.haslayer(IP):
                    src, dst = packet[IP].src, packet[IP].dst
                    for address in (src, dst):
                        try:
                            ipaddress.ip_address(address)
                            _add_indicator(indicators, address, "ip", ts)
                        except ValueError:
                            pass
                    protocols["IPv4"] += 1
                elif packet.haslayer(IPv6):
                    src, dst = packet[IPv6].src, packet[IPv6].dst
                    for address in (src, dst):
                        _add_indicator(indicators, address, "ip", ts)
                    protocols["IPv6"] += 1

                if packet.haslayer(ARP):
                    protocols["ARP"] += 1
                    arp = packet[ARP]
                    events.append(
                        TimelineEvent(
                            ts,
                            "ARP",
                            f"ARP {arp.op} from {arp.psrc} to {arp.pdst}",
                            arp.psrc,
                            arp.pdst,
                        )
                    )

                sport = dport = None
                transport = "Other"
                if packet.haslayer(TCP):
                    layer = packet[TCP]
                    sport, dport, transport = int(layer.sport), int(layer.dport), "TCP"
                    protocols["TCP"] += 1
                    flow_key = _conversation_key(src, dst, sport, dport, transport)
                    conv = conversation_map.setdefault(
                        flow_key, Conversation(transport, src or "?", sport, dst or "?", dport)
                    )
                    conv.packets += 1
                    conv.bytes += size
                    if int(layer.flags) & 0x02 and not int(layer.flags) & 0x10:
                        conv.syn_attempts += 1
                        events.append(
                            TimelineEvent(
                                ts,
                                "TCP connection attempt",
                                f"{src}:{sport} attempted {dst}:{dport}",
                                src,
                                dst,
                                {"destination_port": dport},
                            )
                        )
                    ports[str(dport)] += 1
                elif packet.haslayer(UDP):
                    layer = packet[UDP]
                    sport, dport, transport = int(layer.sport), int(layer.dport), "UDP"
                    protocols["UDP"] += 1
                    flow_key = _conversation_key(src, dst, sport, dport, transport)
                    conv = conversation_map.setdefault(
                        flow_key, Conversation(transport, src or "?", sport, dst or "?", dport)
                    )
                    conv.packets += 1
                    conv.bytes += size
                    ports[str(dport)] += 1
                elif packet.haslayer(ICMP):
                    protocols["ICMP"] += 1
                    events.append(
                        TimelineEvent(
                            ts, "ICMP", f"ICMP type {packet[ICMP].type} observed", src, dst
                        )
                    )

                if src:
                    sources[src] += 1
                if dst:
                    destinations[dst] += 1

                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    query = _text(packet[DNSQR].qname) if packet.haslayer(DNSQR) else ""
                    if query:
                        _add_indicator(indicators, query, "domain", ts)
                        dns_records.append(
                            {
                                "timestamp": ts,
                                "source": src,
                                "destination": dst,
                                "query": query,
                                "response": bool(dns.qr),
                                "answers": [],
                            }
                        )
                        events.append(
                            TimelineEvent(
                                ts,
                                "DNS query" if not dns.qr else "DNS response",
                                f"{src or 'unknown'} {'queried' if not dns.qr else 'received DNS response for'} {query}",
                                src,
                                dst,
                                {"query": query},
                            )
                        )
                    if dns.qr and dns.an:
                        answers: list[str] = []
                        for idx in range(int(dns.ancount or 0)):
                            try:
                                answer = dns.an[idx]
                                value = _text(answer.rdata)
                                if int(answer.type) in (1, 28):
                                    _add_indicator(indicators, value, "ip", ts)
                                elif int(answer.type) in (5, 12, 15):
                                    _add_indicator(indicators, value, "domain", ts)
                                answers.append(value)
                            except (IndexError, AttributeError, TypeError):
                                continue
                        if dns_records:
                            dns_records[-1]["answers"] = answers

                if packet.haslayer(TCP) and hasattr(packet[TCP], "payload"):
                    raw = bytes(packet[TCP].payload)
                    http = _http_metadata(raw)
                    if http:
                        row = {
                            "timestamp": ts,
                            "source": src,
                            "destination": dst,
                            "source_port": sport,
                            "destination_port": dport,
                            **http,
                        }
                        http_records.append(row)
                        if "host" in http:
                            _add_indicator(indicators, http["host"], "hostname", ts)
                            if "method" in http:
                                observed_url = http["path"]
                                if not re.match(r"^https?://", observed_url, re.I):
                                    observed_url = f"http://{http['host']}{observed_url}"
                                _add_indicator(indicators, observed_url, "url", ts)
                        if "user_agent" in http:
                            _add_indicator(indicators, http["user_agent"], "user-agent", ts)
                        if "method" in http:
                            events.append(
                                TimelineEvent(
                                    ts,
                                    "HTTP request",
                                    f"{http['method']} {http.get('host', '')}{http['path']}",
                                    src,
                                    dst,
                                    http,
                                )
                            )
                        elif "status" in http:
                            events.append(
                                TimelineEvent(
                                    ts,
                                    "HTTP response",
                                    f"HTTP status {http['status']}",
                                    src,
                                    dst,
                                    http,
                                )
                            )

                sni = _tls_sni(packet)
                if sni:
                    _add_indicator(indicators, sni, "hostname", ts)
                    tls_records.append(
                        {
                            "timestamp": ts,
                            "source": src,
                            "destination": dst,
                            "server_name": sni,
                            "source_port": sport,
                            "destination_port": dport,
                        }
                    )
                    events.append(
                        TimelineEvent(
                            ts,
                            "TLS SNI",
                            f"TLS server name observed: {sni}",
                            src,
                            dst,
                            {"server_name": sni},
                        )
                    )
            except (ValueError, TypeError, AttributeError, IndexError, KeyError):
                errors += 1
                continue
    except Exception as exc:
        if isinstance(exc, ValueError) and "packet limit" in str(exc):
            raise
        raise ValueError(f"Capture parsing stopped after {count:,} packets: {exc}") from exc
    finally:
        reader.close()

    duration = max(0.0, end - start) if start is not None and end is not None else 0.0
    for conv in conversation_map.values():
        if conv.destination_port is not None and conv.destination_port not in COMMON_PORTS:
            reason = "Traffic used a non-standard destination port; verify whether this is expected in the environment."
            key = ("port", str(conv.destination_port))
            if key not in indicators:
                indicators[key] = Indicator(
                    str(conv.destination_port), "port", "Interesting", reason
                )

    events.sort(key=lambda event: event.timestamp)
    _LOGGER.info(
        "Capture analysis complete: packets=%d events=%d indicators=%d parse_errors=%d",
        count,
        len(events),
        len(indicators),
        errors,
    )
    stats = {
        "total_packets": count,
        "capture_duration_seconds": round(duration, 3),
        "captured_bytes": total_bytes,
        "approx_transferred_bytes": sum(c.bytes for c in conversation_map.values()),
        "protocol_distribution": dict(protocols.most_common()),
        "top_talkers": [{"address": ip, "packets": n} for ip, n in sources.most_common(10)],
        "top_destinations": [
            {"address": ip, "packets": n} for ip, n in destinations.most_common(10)
        ],
        "top_ports": [{"port": port, "packets": n} for port, n in ports.most_common(10)],
        "dns_query_count": sum(1 for row in dns_records if not row["response"]),
        "http_request_count": sum(1 for row in http_records if "method" in row),
        "tcp_connection_attempts": sum(c.syn_attempts for c in conversation_map.values()),
        "parse_errors": errors,
    }
    return CaptureAnalysis(
        capture={
            "file_name": capture_path.name,
            "file_size_bytes": capture_path.stat().st_size,
            "format": "PCAP/PCAPNG (detected by Scapy)",
            "first_packet": iso_timestamp(start) if start is not None else None,
            "last_packet": iso_timestamp(end) if end is not None else None,
        },
        statistics=stats,
        timeline=events,
        indicators=sorted(indicators.values(), key=lambda item: (item.kind, item.value.lower())),
        conversations=sorted(conversation_map.values(), key=lambda c: c.bytes, reverse=True),
        dns=dns_records,
        http=http_records,
        tls=tls_records,
        findings=[
            {
                "title": "Non-standard destination port observed",
                "severity": "Informational",
                "reason": "A non-standard destination port was seen. This is contextual metadata and does not establish malicious activity.",
            }
        ]
        if any(i.kind == "port" for i in indicators.values())
        else [],
    )
