from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

from packetstory.parser import _extract_tls_sni, analyze_capture
from packetstory.report import render_html


def test_analyze_extracts_dns_http_and_stats(tmp_path):
    capture = tmp_path / "sample.pcap"
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="demo.example")),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: demo.example\r\nUser-Agent: UnitTest\r\n\r\n"),
    ]
    packets[0].time = 1000
    packets[1].time = 1002
    wrpcap(str(capture), packets)

    result = analyze_capture(capture)

    assert result.statistics["total_packets"] == 2
    assert result.statistics["dns_query_count"] == 1
    assert result.statistics["http_request_count"] == 1
    assert result.dns[0]["query"] == "demo.example"
    assert result.http[0]["path"] == "/"
    assert {item.value for item in result.indicators} >= {"demo.example", "192.0.2.10"}
    assert "http://demo.example/" in {item.value for item in result.indicators}


def test_extracts_tls_sni_from_visible_client_hello(tmp_path):
    name = b"demo.example"
    server_name = b"\x00" + len(name).to_bytes(2, "big") + name
    name_list = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list
    hello = (
        b"\x03\x03"
        + b"\x01" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extension).to_bytes(2, "big")
        + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    assert _extract_tls_sni(record) == "demo.example"
    assert _extract_tls_sni(record[:20]) is None

    capture = tmp_path / "tls.pcap"
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51515, dport=443)
        / Raw(record)
    )
    wrpcap(str(capture), [packet])
    result = analyze_capture(capture)
    assert result.tls[0]["server_name"] == "demo.example"


def test_conversations_merge_both_tcp_directions(tmp_path):
    capture = tmp_path / "flows.pcap"
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51515, dport=443, flags="S"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=443, dport=51515, flags="SA"),
    ]
    wrpcap(str(capture), packets)
    result = analyze_capture(capture)
    assert len(result.conversations) == 1
    assert result.conversations[0].packets == 2
    assert result.statistics["tcp_connection_attempts"] == 1


def test_report_escapes_capture_and_packet_values(tmp_path):
    capture = tmp_path / "unsafe.pcap"
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="198.51.100.1")
        / TCP(dport=80, sport=1)
        / Raw(b"GET / HTTP/1.1\r\nHost: <img src=x>\r\n\r\n")
    )
    wrpcap(str(capture), [packet])
    result = analyze_capture(capture)
    result.capture["file_name"] = "<unsafe>.pcap"
    report = render_html(result)

    assert "&lt;unsafe&gt;.pcap" in report
    assert "&lt;img src=x&gt;" in report
    assert "<img src=x>" not in report


def test_missing_capture_is_readable_error(tmp_path):
    try:
        analyze_capture(tmp_path / "missing.pcap")
    except FileNotFoundError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")


def test_reads_pcapng_capture(tmp_path):
    capture = tmp_path / "sample.pcapng"
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="198.51.100.1")
        / TCP(sport=50000, dport=443, flags="S")
    )
    writer = PcapNgWriter(str(capture))
    try:
        writer.write(packet)
    finally:
        writer.close()

    result = analyze_capture(capture)

    assert result.statistics["total_packets"] == 1
    assert result.statistics["protocol_distribution"]["TCP"] == 1
