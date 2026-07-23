#!/usr/bin/env python3
"""
Simple Python Port Scanner
------------------------
Educational / authorized-testing tool for checking which ports are
open on a host you own or have explicit permission to scan.

Supports three scan modes:
    connect  - full TCP three-way handshake (default, no root needed)
    syn      - "stealth" TCP SYN scan using raw sockets (needs root/scapy)
    udp      - UDP scan (needs root for reliable ICMP-unreachable reading)

Usage examples:
    python3 scanner.py 192.168.1.10
    python3 scanner.py scanme.example.com -p 1-1024
    python3 scanner.py 10.0.0.5 -p 22,80,443,8080 -t 200 --banner
    sudo python3 scanner.py 10.0.0.5 -p 1-1024 -m syn
    sudo python3 scanner.py 10.0.0.5 -p 53,123,161 -m udp
    python3 scanner.py 10.0.0.5 -p 1-65535 -t 500 -o results/scan.json

IMPORTANT: Only scan systems you own or are explicitly authorized to
test. Unauthorized port scanning may be illegal in your jurisdiction
and can violate the target network's terms of service. SYN scans in
particular are commonly flagged by IDS/IPS systems as an attack.
"""

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def parse_ports(port_spec: str) -> list[int]:
    """Parse a port spec like '80', '1-1024', or '22,80,443,8000-8100'."""
    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Ports out of range (1-65535): {invalid}")
    return sorted(ports)


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float):
    """Try to read a short banner / service string from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.settimeout(1.0)
                data = s.recv(256)
                return data.decode(errors="replace").strip() or None
            except socket.timeout:
                return None
    except Exception:
        return None


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ----------------------------------------------------------------------
# Core scan logic
# ----------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float, do_banner: bool):
    """Attempt a TCP connect to a single port. Returns result dict if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                info = {
                    "port": port,
                    "state": "open",
                    "service": service_name(port),
                }
                if do_banner:
                    banner = grab_banner(ip, port, timeout)
                    if banner:
                        info["banner"] = banner
                return info
    except socket.error:
        pass
    return None


# --- SYN ("stealth") scan --------------------------------------------
#
# A SYN scan sends only the first packet of the TCP handshake (SYN) and
# inspects the reply, without ever completing the handshake:
#   SYN -> SYN/ACK  => port is OPEN   (we reply RST to tear it down)
#   SYN -> RST/ACK  => port is CLOSED
#   SYN -> (nothing)=> port is FILTERED (firewall likely dropping it)
#
# Because the connection is never finished, it's quieter than a full
# connect scan and historically evaded simple logging - hence "stealth".
# Modern IDS/IPS systems detect it easily, so treat the name as
# historical rather than a real guarantee of stealth.
#
# Requires raw-socket privileges (root/sudo on Linux/macOS,
# Administrator on Windows) and the `scapy` package.

def syn_scan_port(ip: str, port: int, timeout: float, src_port: int = None):
    try:
        from scapy.all import IP, TCP, sr1, RandShort
    except ImportError:
        print("[!] SYN scan requires scapy: pip install scapy")
        sys.exit(1)

    sport = src_port or RandShort()
    pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return {"port": port, "state": "filtered", "service": service_name(port)}

    if resp.haslayer(TCP):
        flags = int(resp.getlayer(TCP).flags)
        # Check RST first: RST and SYN+ACK both set the ACK bit (0x10),
        # so a naive "flags & 0x12" check would misclassify a plain
        # RST/ACK (closed) as a SYN/ACK (open). Testing the RST bit
        # (0x04) on its own avoids that overlap.
        if flags & 0x04:  # RST set -> port is closed
            return None
        elif flags & 0x02:  # SYN set (i.e. SYN/ACK) -> port is open
            # send RST to gracefully tear down the half-open connection
            rst = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R")
            sr1(rst, timeout=timeout, verbose=0)
            return {"port": port, "state": "open", "service": service_name(port)}
    elif resp.haslayer(IP) and int(resp.getlayer(IP).proto) == 1:
        return {"port": port, "state": "filtered", "service": service_name(port)}

    return None


# --- UDP scan ----------------------------------------------------------
#
# UDP has no handshake, so "openness" is inferred:
#   - a UDP reply from the service          => OPEN
#   - an ICMP "port unreachable" (type 3,   => CLOSED
#     code 3) error back                    
#   - no response at all                    => OPEN|FILTERED (ambiguous -
#                                                could be open-and-silent,
#                                                or a firewall dropping it)
# This ambiguity is inherent to UDP, not a bug in the scanner - nmap has
# the exact same limitation.

def udp_scan_port(ip: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"", (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                return {"port": port, "state": "open", "service": service_name_udp(port)}
            except socket.timeout:
                # No reply: could be open (silently discarding) or filtered.
                return {"port": port, "state": "open|filtered", "service": service_name_udp(port)}
            except ConnectionResetError:
                # Windows/some stacks surface ICMP unreachable this way
                return None  # closed
    except OSError as e:
        # On Linux, ICMP port-unreachable often surfaces as ECONNREFUSED
        if getattr(e, "errno", None) == 111:
            return None  # closed
        return None


def service_name_udp(port: int) -> str:
    try:
        return socket.getservbyport(port, "udp")
    except OSError:
        return "unknown"


def run_scan(ip, ports, timeout, max_threads, do_banner, quiet, mode="connect"):
    open_ports = []
    total = len(ports)
    scanned = 0
    lock = threading.Lock()

    if mode == "connect":
        worker = lambda p: scan_port(ip, p, timeout, do_banner)
    elif mode == "syn":
        worker = lambda p: syn_scan_port(ip, p, timeout)
    elif mode == "udp":
        worker = lambda p: udp_scan_port(ip, p, timeout)
    else:
        raise ValueError(f"Unknown scan mode: {mode}")

    # SYN scans use raw sockets and aren't safely reentrant across many
    # threads with scapy's default settings, so we cap concurrency there.
    threads = max_threads if mode == "connect" else min(max_threads, 20)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, port): port for port in ports}
        for future in as_completed(futures):
            with lock:
                scanned += 1
                if not quiet:
                    print(f"\r[*] Scanned {scanned}/{total} ports", end="", flush=True)
            result = future.result()
            if result:
                open_ports.append(result)

    if not quiet:
        print()

    return sorted(open_ports, key=lambda r: r["port"])


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------

def print_results(target, ip, open_ports, elapsed):
    print(f"\nScan report for {target} ({ip})")
    print(f"Completed in {elapsed:.2f} seconds\n")

    if not open_ports:
        print("No open ports found.")
        return

    print(f"{'PORT':<10}{'STATE':<16}{'SERVICE':<15}BANNER")
    print("-" * 65)
    for r in open_ports:
        banner = r.get("banner", "")
        print(f"{r['port']:<10}{r['state']:<16}{r['service']:<15}{banner}")


def save_results(path, target, ip, open_ports, elapsed):
    data = {
        "target": target,
        "ip": ip,
        "scanned_at": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 2),
        "open_ports": open_ports,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Results saved to {path}")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Simple multithreaded TCP port scanner (authorized use only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan: single (80), range (1-1024), or list (22,80,443)"
    )
    parser.add_argument(
        "-m", "--mode", choices=["connect", "syn", "udp"], default="connect",
        help="Scan technique: connect (full handshake), syn (stealth, needs root), udp"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent worker threads (auto-capped for syn mode)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket connection timeout in seconds"
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Attempt to grab service banners from open ports"
    )
    parser.add_argument(
        "-o", "--output", help="Save results as JSON to this file path"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress progress output"
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if args.mode in ("syn", "udp"):
        try:
            is_root = (hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0)
        except AttributeError:
            is_root = False  # Windows: skip this check, rely on the OS to error out
        if not is_root and sys.platform != "win32":
            print(f"[!] '{args.mode}' mode needs raw-socket privileges. Re-run with sudo.")
            sys.exit(1)

    if args.mode == "syn" and args.banner:
        print("[!] --banner is ignored in syn mode (no full connection is made).")
        args.banner = False

    ip = resolve_target(args.target)

    print(f"[*] Starting {args.mode.upper()} scan on {args.target} ({ip})")
    print(f"[*] Scanning {len(ports)} port(s) with {args.threads} threads\n")

    start = time.time()
    open_ports = run_scan(ip, ports, args.timeout, args.threads, args.banner, args.quiet, args.mode)
    elapsed = time.time() - start

    print_results(args.target, ip, open_ports, elapsed)

    if args.output:
        save_results(args.output, args.target, ip, open_ports, elapsed)


if __name__ == "__main__":
    main()
