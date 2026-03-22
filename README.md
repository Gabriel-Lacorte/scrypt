# $Crypt Framework

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

**$Crypt** is a next-generation cryptographic analysis framework built in Rust
for security researchers. It delivers high-performance protocol
analysis with zero-copy memory semantics, a modular plugin system, and an interactive
terminal interface.

## Features

- **Protocol Dissection Engine** Zero-copy parsing of Ethernet, IPv4/v6, TCP, UDP, TLS 1.3, DNS, HTTP with extensible dissector framework
- **Plugin System** Native Rust plugins (dylib) + Lua 5.4 scripting with sandboxed execution and hot-reload
- **PCAP Analysis** Read PCAP/PCAPNG files with memory-mapped zero-copy access, parallel dissection via rayon
- **Timing Replay** Replay captured traffic with accurate inter-packet timing reconstruction
- **TLS 1.3 Inspector** Parse handshakes, extract certificates, decrypt with SSLKEYLOGFILE
- **Crypto Engine** AES-256-GCM, ChaCha20-Poly1305 with hardware acceleration
- **Interactive TUI** 3-pane Wireshark-like terminal interface (packet list, protocol tree, hex dump)
- **Sandboxed Execution** seccomp-bpf + Landlock LSM isolation for plugins and analysis
- **Distributed Analysis** gRPC-based mesh networking for processing large captures

## Quick Start

```bash
# Build
cargo build --release

# Analyze a PCAP file
./target/release/$crypt analyze --input capture.pcap

# Interactive TUI
./target/release/$crypt tui --input capture.pcap

# JSON output
./target/release/$crypt analyze --input capture.pcap --format json

# Replay with timing
./target/release/$crypt replay --input capture.pcap --speed 1.0

# System info
./target/release/$crypt info
```

## Writing Plugins

### Lua Plugin

Create a `.lua` file in `plugins/scripts/`:

```lua
plugin = {
    name = "MyProtocol",
    version = "0.1.0",
    author = "Your Name",
    description = "Dissects MyProtocol",
}

function can_dissect(data_len, src_port, dst_port)
    if dst_port == 12345 then return "high" end
    return "none"
end

function dissect(data, src_port, dst_port)
    return {
        protocol = "MyProtocol",
        summary = "MyProtocol message",
        header_len = 8,
        fields = {
            { name = "Type", value = "Request", offset = 0, len = 1 },
        },
    }
end
```

## TUI Keybindings

| Key | Action |
|-----|--------|
| `j`/`k`/`↓`/`↑` | Navigate up/down (scroll hex in Hex Dump pane) |
| `Tab` | Switch pane (Packet List -> Protocol Tree -> Hex Dump) |
| `/` | Enter filter mode |
| `Enter` | Apply filter |
| `Esc` | Cancel filter / Exit |
| `g`/`G` | Jump to first/last (or top/bottom of hex) |
| `q` | Quit |

### Display Filters

The filter bar supports BPF-style expressions:

| Expression | Meaning |
|------------|---------|
| `tcp` | Show only TCP packets |
| `udp` | Show only UDP packets |
| `tls` | Show only TLS packets |
| `port:443` | Match source or destination port |
| `ip.src==10.0.0.1` | Match source IP address |
| `ip.dst==192.168.1.1` | Match destination IP address |
| `field:example.com` | Search all field values |
| `dns` | Plain text search across protocols, summaries, fields |

## Requirements

- Rust 1.76+
- Linux kernel >= 5.15 (for full sandbox support)
- libpcap-dev (for live capture only)

## License

BSD 3-Clause - see [LICENSE](LICENSE)
