#!/usr/bin/env python3
"""
A tiny AbuseIPDB APIv2 CHECK endpoint.

Run:
    python mock_abusedb.py

Try:
    curl -G http://$MOCK_ABUSEDB_HOST:$MOCK_ABUSEDB_PORT/api/v2/check --data-urlencode "ipAddress=203.0.113.88" -d maxAgeInDays=$ABUSEDB_MAX_AGE_DAYS -d verbose -H "Key: $ABUSEDB_API_KEY" -H "Accept: application/json"
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


MOCK_IP_DATA = {
    "185.249.74.198": {
        "abuseConfidenceScore": 92,
        "countryCode": "DE",
        "countryName": "Germany",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "AM Cloud Hosting GmbH",
        "domain": "am-hosting.org",
        "hostnames": ["edge-203-0-113-88.am-hosting.org"],
        "isTor": False,
        "totalReports": 18,
        "numDistinctUsers": 7,
        "lastReportedAt": "2026-05-05T02:29:10+00:00",
        "reports": [
            {
                "reportedAt": "2026-05-05T02:29:10+00:00",
                "comment": "Repeated failed authentication attempts against Azure Portal.",
                "categories": [18, 22],
                "reporterId": 1001,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States",
            },
            {
                "reportedAt": "2026-05-04T21:17:40+00:00",
                "comment": "Credential stuffing activity observed from this address.",
                "categories": [18],
                "reporterId": 1002,
                "reporterCountryCode": "GB",
                "reporterCountryName": "United Kingdom",
            },
        ],
    },
    "198.51.100.24": {
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "countryName": "United States",
        "usageType": "Business",
        "isp": "Sherlock Enterprise Network",
        "domain": "contoso.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "reports": [],
    },
    "192.0.2.45": {
        "abuseConfidenceScore": 5,
        "countryCode": "IE",
        "countryName": "Ireland",
        "usageType": "Business",
        "isp": "Shine Service Provider",
        "domain": "inventory-sync.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 1,
        "numDistinctUsers": 1,
        "lastReportedAt": "2026-04-30T11:04:22+00:00",
        "reports": [
            {
                "reportedAt": "2026-04-30T11:04:22+00:00",
                "comment": "Low-confidence automated scan report.",
                "categories": [14],
                "reporterId": 1003,
                "reporterCountryCode": "IE",
                "reporterCountryName": "Ireland",
            }
        ],
    },
}


def load_env(file_path=".env") -> None:
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :].strip()
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)
    except Exception as e:
        print(f"Error reading {file_path} file: {e}")
        sys.exit(1)


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        print(f"Error: Missing {name}. Add it to .env.")
        sys.exit(1)
    return value


def error_payload(detail: str, status: int, parameter: str | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {
        "detail": detail,
        "status": status,
    }
    if parameter:
        error["source"] = {"parameter": parameter}
    return {"errors": [error]}


def default_record(ip: str) -> dict[str, Any]:
    return {
        "abuseConfidenceScore": 0,
        "countryCode": None,
        "countryName": None,
        "usageType": "Unknown",
        "isp": "Unknown",
        "domain": None,
        "hostnames": [],
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "reports": [],
    }


def check_response(ip: str, verbose: bool) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    record = dict(MOCK_IP_DATA.get(ip, default_record(ip)))
    reports = record.pop("reports", [])
    data = {
        "ipAddress": ip,
        "isPublic": not address.is_private,
        "ipVersion": address.version,
        "isWhitelisted": False,
        **record,
    }
    if not verbose:
        data.pop("countryName", None)
    if verbose:
        data["reports"] = reports
    return {"data": data}


class MockAbuseDBHandler(BaseHTTPRequestHandler):
    server_version = "AbuseDB/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def api_key(self) -> str:
        return self.server.api_key  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        if parsed_url.path != "/api/v2/check":
            self._send_json(404, error_payload("Not Found.", 404))
            return

        if self.headers.get("Key") != self.api_key:
            self._send_json(
                401,
                error_payload("Authentication failed. Your API key is invalid or missing.", 401),
            )
            return

        query = parse_qs(parsed_url.query, keep_blank_values=True)
        ip = query.get("ipAddress", [""])[0]
        max_age = query.get("maxAgeInDays", ["30"])[0] or "30"
        verbose = "verbose" in query

        if not ip:
            self._send_json(422, error_payload("The ip address field is required.", 422, "ipAddress"))
            return

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self._send_json(422, error_payload("The ip address must be a valid IPv4 or IPv6 address.", 422, "ipAddress"))
            return

        try:
            max_age_int = int(max_age)
        except ValueError:
            self._send_json(422, error_payload("The max age in days must be an integer.", 422, "maxAgeInDays"))
            return

        if max_age_int < 1 or max_age_int > 365:
            self._send_json(422, error_payload("The max age in days must be between 1 and 365.", 422, "maxAgeInDays"))
            return

        self._send_json(200, check_response(ip, verbose))

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a tiny AbuseIPDB API server.")
    host = get_required_env("MOCK_ABUSEDB_HOST")
    port = get_required_env("MOCK_ABUSEDB_PORT")
    parser.add_argument("--host", default=host, help=f"host to bind, default: {host}")
    parser.add_argument("--port", type=int, default=int(port), help=f"port to bind, default: {port}")
    parser.add_argument("--api-key", default=get_required_env("MOCK_ABUSEDB_API_KEY"), help="required API key")
    return parser.parse_args()


def main() -> int:
    load_env()
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), MockAbuseDBHandler)
    server.api_key = args.api_key

    print(f"AbuseDB API listening on http://{args.host}:{args.port}")
    print(f"Required Key header: {args.api_key}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down AbuseDB server...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
