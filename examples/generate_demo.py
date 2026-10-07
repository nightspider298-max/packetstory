"""Generate a synthetic, credential-free PCAP for local PacketStory demos."""

import logging
import time
from pathlib import Path

_scapy_logger = logging.getLogger("scapy.loading")
_scapy_level = _scapy_logger.level
_scapy_logger.setLevel(logging.ERROR)
try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.utils import wrpcap
finally:
    _scapy_logger.setLevel(_scapy_level)


def main() -> None:
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="demo.example")),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51515, dport=80, flags="PA")
        / Raw(
            b"GET /health HTTP/1.1\r\nHost: demo.example\r\nUser-Agent: PacketStory-Demo/1.0\r\n\r\n"
        ),
    ]
    for index, packet in enumerate(packets):
        packet.time = time.time() + index * 3
    output = Path(__file__).with_name("packetstory-demo.pcap")
    wrpcap(str(output), packets)
    print(f"Wrote {output.name} (synthetic documentation-range traffic).")


if __name__ == "__main__":
    main()
