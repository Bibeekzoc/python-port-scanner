# Python Port Scanner

A simple, multithreaded TCP port scanner built with Python's standard library.

## ⚠️ Authorized use only
Only scan hosts you own or have explicit written permission to test.
Unauthorized scanning may be illegal and can violate network terms of service.

## Usage

```bash
python3 scanner.py <target> [options]
```

| Option | Description | Default |
|---|---|---|
| `target` | Hostname or IP to scan | required |
| `-p, --ports` | Ports: `80`, `1-1024`, or `22,80,443` | `1-1024` |
| `-m, --mode` | Scan technique: `connect`, `syn`, `udp` | `connect` |
| `-t, --threads` | Concurrent worker threads (`syn` auto-caps at 20) | `100` |
| `--timeout` | Per-connection timeout (seconds) | `1.0` |
| `--banner` | Attempt banner grabbing (`connect` mode only) | off |
| `-o, --output` | Save results as JSON | none |
| `-q, --quiet` | Suppress progress output | off |

## Scan modes
- **connect** (default, no root) — full TCP handshake, most reliable, supports `--banner`.
- **syn** (needs root + `scapy`) — "stealth" half-open SYN scan, faster, no banners.
- **udp** (needs root recommended) — UDP scan; results may report `open|filtered`, which is inherent to UDP.

See **`SCAN_MODES.txt`** for a full technical explanation of how each mode works, what it needs, and when to use it.

## Examples

```bash
# Scan common ports on localhost (connect mode)
python3 scanner.py 127.0.0.1 -p 1-1024

# Scan specific ports with banner grabbing
python3 scanner.py scanme.nmap.org -p 22,80,443 --banner

# Stealth SYN scan (needs sudo + scapy)
sudo python3 scanner.py 10.0.0.5 -m syn -p 1-1024

# UDP scan of common services (needs sudo)
sudo python3 scanner.py 10.0.0.5 -m udp -p 53,67,123,161

# Full port sweep, save to file
python3 scanner.py 192.168.1.1 -p 1-65535 -t 300 -o results/scan.json
```

## How it works
- **connect**: opens a TCP socket and calls `connect_ex()`. A return value
  of `0` means the three-way handshake succeeded — the port is open.
- **syn**: sends a raw SYN packet via `scapy` and inspects the reply
  (SYN/ACK = open, RST = closed, no reply = filtered) without completing
  the handshake.
- **udp**: sends an empty UDP datagram; a reply means open, an ICMP
  port-unreachable means closed, and silence means `open|filtered`.

Work is distributed across a thread pool for speed in all three modes.
