# Analysis scope and limitations

- PacketStory uses Scapy's offline readers and dissection layers; malformed packets and unsupported link types may not decode.
- HTTP support is a single-packet, visible HTTP/1 start-line/header parser. It does not reassemble TCP streams, inspect bodies, decode HTTP/2, or recover encrypted data.
- TLS SNI is extracted only from a complete visible ClientHello in one captured TCP segment. Fragmented handshakes, TLS 1.3 encrypted handshake data, and ECH may conceal names. Certificate fields are not extracted in v0.1.0.
- Byte counts are packet lengths. Retransmission, capture truncation, offload, and asymmetric capture affect interpretation.
- “Interesting” non-standard ports are contextual prompts. They are not threat verdicts.
- Packet processing stops above two million packets by default to bound resource use.
