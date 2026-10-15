#!/usr/bin/env python3
"""AirSentinel Core — Command Line Launcher and Server Host."""
import argparse
import socket
import sys
import uvicorn
from airsentinel.config import settings

def get_lan_ip() -> str:
    """Discovers the local LAN IP address of this Mac."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def print_banner(host: str, port: int):
    lan_ip = get_lan_ip()
    print("=" * 64)
    print("       AIRSENTINEL CORE — TACTICAL RF PERIMETER SENTINEL       ")
    print("=" * 64)
    print(f" Engine Status : ONLINE (v{settings.app_version})")
    print(f" Catalog Rules : 6,973 indexed signatures (Fieldwatch v94)")
    print(f" Local Web UI  : http://localhost:{port}")
    print(f" LAN Access    : http://{lan_ip}:{port}")
    print("=" * 64)
    print(" Press Ctrl+C to stop.\n")

def main():
    parser = argparse.ArgumentParser(description="Launch AirSentinel Core")
    parser.add_argument("--host", default=settings.host, help="Host address to bind")
    parser.add_argument("--port", type=int, default=settings.port, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        settings.debug = True

    print_banner(args.host, args.port)

    uvicorn.run(
        "airsentinel.web.app:app",
        host=args.host,
        port=args.port,
        log_level="info" if not args.debug else "debug",
    )

if __name__ == "__main__":
    main()
