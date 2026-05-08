#!/usr/bin/env python3
"""
A tiny Ollama-compatible API server.

Run:
    python main.py

Try:
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/tags
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/version
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/show -H "Content-Type: application/json" -d '{}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/generate -H "Content-Type: application/json" -d '{"prompt":"hello","stream":false}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/generate -H "Content-Type: application/json" -d '{"prompt":"You are a SOC Triage Assistant. Analyze the provided JSON alert and output a triage summary in json format with exactly these four sections for each alert: 1.Log Id 2. Severity Guess: (e.g., Low, Medium, High, Critical) 3. Meaning: (What the alert probably indicates) 4. Suggested Next Step: (What the analyst should do next)","stream":false}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/chat -H "Content-Type: application/json" -d '{"messages":[{"role":"user","content":"hello"}],"stream":false}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/embeddings -H "Content-Type: application/json" -d '{"prompt":"hello"}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/api/embed -H "Content-Type: application/json" -d '{"input":"hello"}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/v1/models
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/v1/chat/completions -H "Content-Type: application/json" -d '{"messages":[{"role":"user","content":"hello"}]}'
    curl http://$MOCK_OLLAMA_HOST:$MOCK_OLLAMA_PORT/v1/completions -H "Content-Type: application/json" -d '{"prompt":"hello"}'
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


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


MODEL_CATALOG = {
    "qwen:0.5b": {
        "family": "qwen",
        "architecture": "qwen",
        "parameter_size": "0.5B",
        "supports_tools": False,
        "size": 320_000_000,
    },
    "qwen2.5:1.5b": {
        "family": "qwen2.5",
        "architecture": "qwen2",
        "parameter_size": "1.5B",
        "supports_tools": True,
        "size": 986_000_000,
    },
}


IDENTITY_QUESTIONS = {
    "who are you",
    "who are u",
    "who r you",
    "who r u",
    "who you",
    "who u",
}
IDENTITY_RESPONSES = {
    "qwen:0.5b": (
        "I am qwen:0.5b, an LLM served through an Ollama-compatible API. "
    ),
    "qwen2.5:1.5b": (
        "I am qwen2.5:1.5b, an LLM served through an Ollama-compatible API. "
    ),
}


QWEN_HELLO_CONTEXT = [
    151644,
    8948,
    198,
    2610,
    525,
    1207,
    16948,
    11,
    3465,
    553,
    54364,
    14817,
    13,
    1446,
    525,
    264,
    10950,
    17847,
    13,
    151645,
    198,
    151644,
    872,
    198,
    14990,
    151645,
    198,
    151644,
    77091,
    198,
    9707,
    0,
    2585,
    646,
    358,
    1492,
    498,
    3351,
    30,
]
QWEN_HELLO_STATS = {
    "total_duration": 469871094,
    "load_duration": 81892115,
    "prompt_eval_count": 30,
    "prompt_eval_duration": 24346713,
    "eval_count": 10,
    "eval_duration": 352090261,
}
SOC_TRIAGE_RESPONSE = [
    {
        "Log Id": "entra-log-0001",
        "Severity Guess": "Low",
        "Meaning": "Successful user login with MFA from a managed and compliant device. Normal authentication behavior.",
        "Suggested Next Step": "No action required. Continue monitoring for anomalies.",
    },
    {
        "Log Id": "entra-log-0002",
        "Severity Guess": "Low",
        "Meaning": "Service principal authenticated successfully using client credentials. Expected for application-to-application communication.",
        "Suggested Next Step": "Verify that the service principal and IP location are expected. No immediate action if known.",
    },
    {
        "Log Id": "entra-log-0003",
        "Severity Guess": "Medium",
        "Meaning": "Multiple failed login attempts (4) for an admin account from an unmanaged and non-compliant device. Potential brute force or credential misuse attempt.",
        "Suggested Next Step": "Investigate source IP and user activity. Check if this behavior is expected and consider conditional access or blocking the IP.",
    },
    {
        "Log Id": "entra-log-0004",
        "Severity Guess": "High",
        "Meaning": "Successful login to admin account shortly after multiple failures from the same IP and non-compliant device. Possible account compromise.",
        "Suggested Next Step": "Immediately verify user activity, enforce password reset, review session tokens, and check for malicious actions.",
    },
    {
        "Log Id": "entra-log-0005",
        "Severity Guess": "High",
        "Meaning": "New authentication method (Authenticator app) registered for admin account following suspicious login pattern. Potential persistence mechanism.",
        "Suggested Next Step": "Validate with the user if this change was legitimate. Remove unauthorized MFA methods and secure the account.",
    },
    {
        "Log Id": "entra-log-0006",
        "Severity Guess": "Critical",
        "Meaning": "Admin account added another account to Global Administrator role. High-risk privilege escalation following suspicious login activity.",
        "Suggested Next Step": "Immediately review and potentially revoke the role assignment. Investigate both accounts for compromise and audit all recent privileged actions.",
    },
    {
        "Log Id": "entra-log-0007",
        "Severity Guess": "Low",
        "Meaning": "User added to a Microsoft 365 group by helpdesk. Likely routine administrative activity.",
        "Suggested Next Step": "No action required unless the group membership change is unexpected.",
    },
    {
        "Log Id": "entra-log-0008",
        "Severity Guess": "Medium",
        "Meaning": "Password reset performed by helpdesk. Could be legitimate support activity.",
        "Suggested Next Step": "Confirm with user or ticketing system that the reset was authorized.",
    },
    {
        "Log Id": "entra-log-0009",
        "Severity Guess": "Low",
        "Meaning": "User granted delegated consent to an application with minimal permissions. Likely normal user activity.",
        "Suggested Next Step": "Verify application legitimacy and ensure permissions align with policy.",
    },
    {
        "Log Id": "entra-log-0010",
        "Severity Guess": "Low",
        "Meaning": "Login failure due to expired password. No indication of malicious activity.",
        "Suggested Next Step": "User should reset password. No further action required.",
    },
    {
        "Log Id": "entra-log-0011",
        "Severity Guess": "Low",
        "Meaning": "Successful login with MFA from compliant device. Normal behavior.",
        "Suggested Next Step": "No action required.",
    },
    {
        "Log Id": "entra-log-0012",
        "Severity Guess": "Low",
        "Meaning": "Successful login with MFA from compliant device. Appears normal.",
        "Suggested Next Step": "No action required.",
    },
]
SOC_LOG_IPS = {
    "entra-log-0001": "198.51.100.24",
    "entra-log-0002": "192.0.2.45",
    "entra-log-0003": "203.0.113.88",
    "entra-log-0004": "203.0.113.88",
    "entra-log-0005": "203.0.113.88",
    "entra-log-0006": "203.0.113.88",
    "entra-log-0007": "198.51.100.63",
    "entra-log-0008": "198.51.100.63",
    "entra-log-0009": "203.0.113.56",
    "entra-log-0010": "192.0.2.219",
    "entra-log-0011": "78.128.113.74",
    "entra-log-0012": "185.249.74.198",
}
SOC_SEVERITY_ORDER = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}
SOC_ALERT_REQUIRED_RESPONSE = (
    "Sure! Please send me the alert file and I will guess the severity "
    "(e.g., Low, Medium, High, Critical) and suggest the next step."
)


def utc_now() -> str:
    now_ns = time.time_ns()
    seconds, nanoseconds = divmod(now_ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{nanoseconds:09d}Z"


def ns_since(start_ns: int) -> int:
    return max(1, time.perf_counter_ns() - start_ns)


def normalized(text: str) -> str:
    return " ".join((text or "").split()).lower().strip(" .!?")


def normalized_question(text: str) -> str:
    cleaned = re.sub(r"[^a-z0-9\s]", " ", (text or "").lower())
    return " ".join(cleaned.split())


def is_identity_question(text: str) -> bool:
    cleaned = normalized_question(text)
    if cleaned in IDENTITY_QUESTIONS:
        return True

    return bool(re.search(r"\bwho\s+(are\s+)?(r\s+)?(you|u)\b", cleaned))


def identity_response(model: str) -> str:
    return IDENTITY_RESPONSES.get(
        model,
        f"I am {model}, a lab LLM served through an Ollama-compatible API.",
    )


def is_qwen05_model(model: str) -> bool:
    return normalized(model) in {"qwen:0.5b", "qwen0.5b"}


def approx_token_count(text: str) -> int:
    compact = " ".join((text or "").split())
    if not compact:
        return 0
    return max(len(compact.split()), (len(compact) + 3) // 4)


def is_soc_triage_prompt(text: str) -> bool:
    cleaned = normalized(text)
    if "soc triage assistant" not in cleaned:
        return False

    return (
        "analyze the provided json alert" in cleaned
        or "analyze this alert" in cleaned
        or "triage summary" in cleaned
        or ("severity guess" in cleaned and "suggested next step" in cleaned)
    )


def has_soc_alert_payload(text: str) -> bool:
    if re.search(r"\bentra-log-\d{4}\b", text or ""):
        return True

    return (
        '"logs"' in (text or "")
        and '"ipAddress"' in (text or "")
        and '"operationName"' in (text or "")
    )


def qwen05_soc_response() -> str:
    file_path = os.path.join(os.path.dirname(__file__), "qwen0.5response.txt")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        weak_items: list[dict[str, Any]] = []
        for item in SOC_TRIAGE_RESPONSE:
            weak_item = {
                "LogId": item["Log Id"],
                "SeverityGuess": "Low" if item["Severity Guess"] in {"Medium", "High", "Critical"} else "Informational",
                "Meaning": item["Meaning"],
                "SuggestedNextStep": item["Suggested Next Step"],
            }
            weak_items.append(weak_item)
        return "```json\n" + json.dumps(weak_items, indent=2) + "\n```"


def soc_triage_response_for_model(model: str, prompt: str) -> str:
    if not has_soc_alert_payload(prompt):
        return SOC_ALERT_REQUIRED_RESPONSE

    if is_qwen05_model(model):
        return qwen05_soc_response()

    return json.dumps(filter_soc_items([dict(item) for item in SOC_TRIAGE_RESPONSE], prompt), indent=2)


def extract_ipv4s(text: str) -> list[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    ips: list[str] = []
    for candidate in candidates:
        parts = candidate.split(".")
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts) and candidate not in ips:
            ips.append(candidate)
    return ips


def pick_ips_for_reputation(text: str) -> list[str]:
    ips = extract_ipv4s(text)
    if is_soc_triage_prompt(text):
        return ips

    suspicious_ips = {"203.0.113.88", "185.249.74.198", "185.220.101.1", "45.155.205.233"}
    selected = [ip for ip in ips if ip in suspicious_ips]
    return selected or ips[:1]


def pick_ip_for_reputation(text: str) -> str | None:
    ips = pick_ips_for_reputation(text)
    return ips[0] if ips else None


def parse_tool_result_content(content: Any) -> dict[str, Any]:
    text = text_from_content(content)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    return parsed if isinstance(parsed, dict) else {"raw": parsed}


def get_tool_results(messages: Any) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(messages, list):
        return []

    results: list[tuple[str, dict[str, Any]]] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "tool":
            continue
        name = message.get("name") or message.get("tool_name")
        if not name:
            continue
        results.append((str(name), parse_tool_result_content(message.get("content"))))
    return results


def get_latest_tool_result(messages: Any) -> tuple[str, dict[str, Any]] | None:
    results = get_tool_results(messages)
    if results:
        return results[-1]
    return None


def find_reputation_tool(tools: Any) -> dict[str, Any] | None:
    if not isinstance(tools, list):
        return None

    best_tool: dict[str, Any] | None = None
    best_score = 0
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        if not isinstance(function, dict):
            continue

        name = str(function.get("name") or "")
        description = str(function.get("description") or "")
        parameters = function.get("parameters") if isinstance(function.get("parameters"), dict) else {}
        properties = parameters.get("properties") if isinstance(parameters.get("properties"), dict) else {}
        required = parameters.get("required") if isinstance(parameters.get("required"), list) else []
        searchable = f"{name} {description} {' '.join(properties.keys())}".lower()

        score = 0
        if "ip" in searchable:
            score += 2
        if "reputation" in searchable or "abuse" in searchable:
            score += 3
        if "ip" in properties:
            score += 2
        if "ip" in required:
            score += 1

        if score > best_score:
            best_score = score
            best_tool = function

    if not best_tool or best_score < 3:
        return None
    return best_tool


def build_reputation_tool_call(tool: dict[str, Any], ip: str, index: int) -> dict[str, Any]:
    parameters = tool.get("parameters") if isinstance(tool.get("parameters"), dict) else {}
    properties = parameters.get("properties") if isinstance(parameters.get("properties"), dict) else {}
    argument_name = "ip" if isinstance(properties, dict) and "ip" in properties else "ipAddress"
    argument_schema = properties.get(argument_name) if isinstance(properties.get(argument_name), dict) else {}
    return {
        "id": f"call_{uuid.uuid4().hex[:8]}",
        "function": {
            "index": index,
            "name": tool.get("name"),
            "arguments": {
                argument_name: {
                    "description": argument_schema.get("description", "The IPv4 address to check."),
                    "type": argument_schema.get("type", "string"),
                    "value": ip,
                },
            },
        },
    }


def select_tool_calls(tools: Any, prompt: str) -> list[dict[str, Any]]:
    ips = pick_ips_for_reputation(prompt)
    best_tool = find_reputation_tool(tools)
    if not ips or not best_tool:
        return []

    return [build_reputation_tool_call(best_tool, ip, index) for index, ip in enumerate(ips)]


def select_tool_call(tools: Any, prompt: str) -> dict[str, Any] | None:
    calls = select_tool_calls(tools, prompt)
    return calls[0] if calls else None


def requested_soc_log_ids(text: str) -> list[str]:
    ids = re.findall(r"\bentra-log-\d{4}\b", text or "")
    selected: list[str] = []
    for log_id in ids:
        if log_id not in selected:
            selected.append(log_id)
    return selected


def filter_soc_items(items: list[dict[str, Any]], prompt: str) -> list[dict[str, Any]]:
    selected_ids = requested_soc_log_ids(prompt)
    if not selected_ids:
        return items
    selected_set = set(selected_ids)
    return [item for item in items if item.get("Log Id") in selected_set]


def highest_severity(current: str, candidate: str) -> str:
    if SOC_SEVERITY_ORDER.get(candidate, 0) > SOC_SEVERITY_ORDER.get(current, 0):
        return candidate
    return current


def severity_from_ip_reputation(score: Any) -> str | None:
    if not isinstance(score, int):
        return None
    if score >= 80:
        return "High"
    if score >= 40:
        return "Medium"
    return None


def reputation_data_by_ip(tool_results: list[tuple[str, dict[str, Any]]] | dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(tool_results, dict):
        iterable: list[tuple[str, dict[str, Any]]] = [("tool", tool_results)]
    else:
        iterable = tool_results

    reputations: dict[str, dict[str, Any]] = {}
    for _name, payload in iterable:
        data = payload.get("data", payload)
        if not isinstance(data, dict):
            continue
        ip = data.get("ipAddress")
        if ip:
            reputations[str(ip)] = data
    return reputations


def apply_ip_reputation(item: dict[str, Any], reputation: dict[str, Any]) -> None:
    ip = str(reputation.get("ipAddress", "unknown"))
    score = reputation.get("abuseConfidenceScore", "unknown")
    reports = reputation.get("totalReports", "unknown")
    isp = reputation.get("isp") or "unknown ISP"
    last_reported = reputation.get("lastReportedAt") or "not reported"
    severity = severity_from_ip_reputation(score)

    if severity is None:
        return

    next_step = str(item.get("Suggested Next Step", ""))
    if next_step.startswith("No action required."):
        next_step = "Validate whether this activity was expected."

    item["Severity Guess"] = highest_severity(str(item.get("Severity Guess", "Low")), severity)
    item["Meaning"] += (
        f" AbuseDB reports source IP {ip} from {isp} with abuseConfidenceScore {score}, "
        f"{reports} total reports, and lastReportedAt {last_reported}."
    )
    item["Suggested Next Step"] = next_step + (
        f" Treat {ip} as suspicious: validate the user activity, review/revoke active sessions, "
        "inspect related device and account activity, and consider blocking the IP."
    )


def soc_response_with_ip_reputation(
    tool_results: list[tuple[str, dict[str, Any]]] | dict[str, Any],
    prompt: str = "",
) -> str:
    reputations = reputation_data_by_ip(tool_results)
    enriched = [dict(item) for item in SOC_TRIAGE_RESPONSE]

    for item in enriched:
        ip = SOC_LOG_IPS.get(str(item.get("Log Id")))
        reputation = reputations.get(ip or "")
        if reputation:
            apply_ip_reputation(item, reputation)

    return json.dumps(filter_soc_items(enriched, prompt), indent=2)


def conversation_uses_tools(messages: Any) -> bool:
    if not isinstance(messages, list):
        return False

    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "tool":
            return True
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            return True
    return False


def ip_reputation_tool_response(tool_result: dict[str, Any]) -> str:
    data = tool_result.get("data", tool_result)
    if not isinstance(data, dict):
        return "I could not parse the IP reputation result."

    ip = data.get("ipAddress", "unknown")
    isp = data.get("isp") or "not provided"
    usage = data.get("usageType") or "not provided"
    country_code = data.get("countryCode") or "unknown"
    country_name = data.get("countryName") or "unknown"
    whitelisted = data.get("isWhitelisted")
    score = data.get("abuseConfidenceScore", "unknown")
    domain = data.get("domain") or "not provided"
    hostnames = data.get("hostnames") if isinstance(data.get("hostnames"), list) else []
    total_reports = data.get("totalReports", "unknown")
    distinct_users = data.get("numDistinctUsers", "unknown")
    last_reported = data.get("lastReportedAt") or "not reported"
    reports = data.get("reports") if isinstance(data.get("reports"), list) else []
    is_tor = data.get("isTor")

    if whitelisted is True:
        whitelist_text = "It has been whitelisted by the system."
    elif whitelisted is False:
        whitelist_text = "It is not whitelisted by the system."
    else:
        whitelist_text = "The whitelist status is not provided."

    if isinstance(score, int):
        if score >= 80:
            score_text = "which suggests a high level of concern."
        elif score >= 40:
            score_text = "which suggests there may be some reason for concern."
        else:
            score_text = "which suggests low concern."
    else:
        score_text = "which could not be scored from the response."

    hostname_text = ""
    if hostnames:
        hostname_text = f" It also has hostname {hostnames[0]}."

    categories: list[str] = []
    reporter_countries: list[str] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        for category in report.get("categories", []):
            category_text = str(category)
            if category_text not in categories:
                categories.append(category_text)
        country = report.get("reporterCountryName") or report.get("reporterCountryCode")
        if country and str(country) not in reporter_countries:
            reporter_countries.append(str(country))

    category_text = "No report categories are provided."
    if categories:
        category_text = "Report categories include " + ", ".join(categories) + "."

    reporter_text = "No reporter country information is provided."
    if reporter_countries:
        reporter_text = "Reports came from " + ", ".join(reporter_countries) + "."

    tor_text = "No Tor exit node is associated with this IP address."
    if is_tor is True:
        tor_text = "This IP address is associated with a Tor exit node."
    elif is_tor is None:
        tor_text = "Tor exit-node status is not provided."

    return (
        f"The IP address {ip} is registered to {isp} and is used for {usage} in "
        f"{country_name} (country code: {country_code}). {whitelist_text} "
        f"The IP's abuse confidence score is {score} out of 100, {score_text}\n\n"
        f"The domain name provided corresponds to the IP address: {domain}.{hostname_text}\n\n"
        f"This IP address has been reported {total_reports} times in total and belongs to "
        f"{distinct_users} distinct reporting users as of the last report. It was last "
        f"reported at {last_reported}. {category_text}\n\n"
        f"{reporter_text} {tor_text}"
    )


def generate_context(prompt: str, response: str) -> list[int]:
    if normalized(prompt) == "hello":
        return QWEN_HELLO_CONTEXT[:]

    prompt_tokens = max(1, approx_token_count(prompt) + 29)
    response_tokens = max(1, approx_token_count(response))
    target_count = max(24, min(8192, prompt_tokens + response_tokens))
    seed = f"{prompt}\n{response}".encode("utf-8")
    context = [151644, 8948, 198]
    counter = 0

    while len(context) < target_count - 5:
        digest = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
        for index in range(0, len(digest), 2):
            if len(context) >= target_count - 5:
                break
            token = digest[index] * 256 + digest[index + 1]
            if len(context) % 41 == 0:
                token = 151645
            elif len(context) % 13 == 0:
                token = 198
            context.append(token)

    context.extend([151645, 198, 151644, 77091, 198])
    return context


def generate_stats(start_ns: int, prompt: str, response: str) -> dict[str, int]:
    if normalized(prompt) == "hello":
        return dict(QWEN_HELLO_STATS)

    prompt_eval_count = max(1, approx_token_count(prompt) + 29)
    eval_count = max(1, approx_token_count(response))
    load_duration = 80_000_000
    prompt_eval_duration = 20_000_000 + prompt_eval_count * 150_000
    eval_duration = 30_000_000 + eval_count * 30_000_000
    total_duration = max(
        ns_since(start_ns),
        load_duration + prompt_eval_duration + eval_duration + 10_000_000,
    )
    return {
        "total_duration": total_duration,
        "load_duration": load_duration,
        "prompt_eval_count": prompt_eval_count,
        "prompt_eval_duration": prompt_eval_duration,
        "eval_count": eval_count,
        "eval_duration": eval_duration,
    }


def chat_stats(
    start_ns: int,
    prompt: str,
    response: str,
    is_tool_call: bool = False,
    is_tool_result: bool = False,
) -> dict[str, int]:
    if is_tool_call:
        load_duration = 1_059_283_447
        prompt_eval_count = max(120, approx_token_count(prompt) + 167)
        prompt_eval_duration = 1_560_137_410
        eval_count = 54
        eval_duration = 1_968_178_172
    elif is_tool_result:
        load_duration = 1_054_620_736
        prompt_eval_count = max(323, approx_token_count(prompt) + 29)
        prompt_eval_duration = 2_730_855_736
        eval_count = max(274, approx_token_count(response))
        eval_duration = 9_211_033_446
    else:
        load_duration = 1_054_620_736
        prompt_eval_count = max(1, approx_token_count(prompt) + 29)
        prompt_eval_duration = 850_000_000 + prompt_eval_count * 5_800_000
        eval_count = max(1, approx_token_count(response))
        eval_duration = 1_000_000_000 + eval_count * 30_000_000

    total_duration = max(
        ns_since(start_ns),
        load_duration + prompt_eval_duration + eval_duration + 40_000_000,
    )
    return {
        "total_duration": total_duration,
        "load_duration": load_duration,
        "prompt_eval_count": prompt_eval_count,
        "prompt_eval_duration": prompt_eval_duration,
        "eval_count": eval_count,
        "eval_duration": eval_duration,
    }


def is_supported_model(model: str) -> bool:
    return model in MODEL_CATALOG


def model_supports_tools(model: str) -> bool:
    return bool(MODEL_CATALOG.get(model, {}).get("supports_tools"))


def model_details(model: str) -> dict[str, Any]:
    config = MODEL_CATALOG.get(model, MODEL_CATALOG["qwen2.5:1.5b"])
    family = str(config["family"])
    return {
        "parent_model": "",
        "format": "gguf",
        "family": family,
        "families": [family],
        "parameter_size": str(config["parameter_size"]),
        "quantization_level": "none",
    }


def tag_payload(model: str) -> dict[str, Any]:
    config = MODEL_CATALOG.get(model, MODEL_CATALOG["qwen2.5:1.5b"])
    digest = hashlib.sha256(model.encode("utf-8")).hexdigest()
    return {
        "name": model,
        "model": model,
        "modified_at": "2026-01-01T00:00:00Z",
        "size": int(config["size"]),
        "digest": f"sha256:{digest}",
        "details": model_details(model),
    }


def text_from_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return json.dumps(content, separators=(",", ":"))
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    parts.append(json.dumps(item, separators=(",", ":")))
        return " ".join(parts)
    return json.dumps(content, separators=(",", ":"))


def prompt_from_messages(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""

    lines: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "user"))
        content = text_from_content(message.get("content"))
        if content:
            lines.append(f"{role}: {content}")
    return "\n".join(lines)


def last_user_message(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""

    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            return text_from_content(message.get("content"))
    return ""


def make_mock_response(model: str, prompt: str, messages: Any = None) -> str:
    prompt = " ".join((prompt or "").split())
    last_user = " ".join(last_user_message(messages).split()) if messages is not None else ""
    target = last_user or prompt

    if not target:
        return "I don't know the response to that."
    if normalized(target) in ("hello", "hi", "hey"):
        return "Hello! How can I help you today?"
    if is_soc_triage_prompt(target):
        return soc_triage_response_for_model(model, target)
    if is_identity_question(target):
        return identity_response(model)

    return "I don't know the response to that."


def split_for_stream(text: str) -> list[str]:
    if not text:
        return [""]

    chunks: list[str] = []
    words = text.split(" ")
    for index, word in enumerate(words):
        suffix = " " if index < len(words) - 1 else ""
        chunks.append(word + suffix)
    return chunks


def embedding_for(text: str, dims: int | None = None) -> list[float]:
    if dims is None:
        dims = int(get_required_env("MOCK_OLLAMA_EMBEDDING_DIMS"))
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    values: list[float] = []
    while len(values) < dims:
        for byte in digest:
            values.append(round((byte / 127.5) - 1.0, 6))
            if len(values) == dims:
                break
        digest = hashlib.sha256(digest).digest()
    return values


class MockOllamaHandler(BaseHTTPRequestHandler):
    server_version = "Ollama/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def model(self) -> str:
        return self.server.mock_model  # type: ignore[attr-defined]

    @property
    def processing_delay(self) -> float:
        return self.server.processing_delay  # type: ignore[attr-defined]

    @property
    def stream_delay(self) -> float:
        return self.server.stream_delay  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send_text(200, "Ollama is running")
        elif path == "/api/version":
            self._send_json(200, {"version": "0.0.0"})
        elif path == "/api/tags":
            self._send_json(200, {"models": [tag_payload(model) for model in MODEL_CATALOG]})
        elif path == "/v1/models":
            self._send_json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": model,
                            "object": "model",
                            "created": 1767225600,
                            "owned_by": "tryhackme",
                        }
                        for model in MODEL_CATALOG
                    ],
                },
            )
        else:
            self._send_error(404, f"unknown route: {path}")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = self._read_json()
        if body is None:
            return

        if path == "/api/generate":
            self._handle_generate(body)
        elif path == "/api/chat":
            self._handle_chat(body)
        elif path == "/api/show":
            self._handle_show(body)
        elif path == "/api/embeddings":
            self._handle_legacy_embeddings(body)
        elif path == "/api/embed":
            self._handle_embed(body)
        elif path == "/v1/chat/completions":
            self._handle_openai_chat(body)
        elif path == "/v1/completions":
            self._handle_openai_completion(body)
        else:
            self._send_error(404, f"unknown route: {path}")

    def _read_json(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"

        try:
            parsed = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            self._send_error(400, f"invalid JSON: {exc.msg}")
            return None

        if not isinstance(parsed, dict):
            self._send_error(400, "request body must be a JSON object")
            return None
        return parsed

    def _requested_model(self, body: dict[str, Any]) -> str | None:
        model = str(body.get("model") or self.model)
        if not is_supported_model(model):
            self._send_error(404, f"model '{model}' not found")
            return None
        return model

    def _handle_generate(self, body: dict[str, Any]) -> None:
        start_ns = time.perf_counter_ns()
        model = self._requested_model(body)
        if model is None:
            return
        prompt = text_from_content(body.get("prompt"))
        if not prompt.strip():
            response = SOC_ALERT_REQUIRED_RESPONSE
            stream = False
        elif is_qwen05_model(model) and is_soc_triage_prompt(prompt):
            response = soc_triage_response_for_model(model, prompt)
            stream = bool(body.get("stream", True))
        else:
            response = make_mock_response(model, prompt)
            stream = bool(body.get("stream", True))
        time.sleep(self.processing_delay)

        if stream:
            self._stream_generate(model, prompt, response, start_ns)
            return

        self._send_json(
            200,
            {
                "model": model,
                "created_at": utc_now(),
                "response": response,
                "done": True,
                "done_reason": "stop",
                "context": generate_context(prompt, response),
                **generate_stats(start_ns, prompt, response),
            },
        )

    def _stream_generate(self, model: str, prompt: str, response: str, start_ns: int) -> None:
        self._start_jsonl_stream()
        count = 0
        for chunk in split_for_stream(response):
            count += 1
            self._write_jsonl(
                {
                    "model": model,
                    "created_at": utc_now(),
                    "response": chunk,
                    "done": False,
                }
            )
            time.sleep(self.stream_delay)

        self._write_jsonl(
            {
                "model": model,
                "created_at": utc_now(),
                "response": "",
                "done": True,
                "done_reason": "stop",
                "context": generate_context(prompt, response),
                **generate_stats(start_ns, prompt, response),
            }
        )

    def _handle_chat(self, body: dict[str, Any]) -> None:
        start_ns = time.perf_counter_ns()
        model = self._requested_model(body)
        if model is None:
            return
        messages = body.get("messages", [])
        prompt = prompt_from_messages(messages)
        stream = bool(body.get("stream", True))
        tool_results = get_tool_results(messages)
        tool_result = tool_results[-1] if tool_results else None
        has_tool_result = bool(tool_results)
        tools = body.get("tools")

        if not model_supports_tools(model) and ((isinstance(tools, list) and tools) or conversation_uses_tools(messages)):
            self._send_error(400, f"registry.ollama.ai/library/{model} does not support tools")
            return

        if tool_results and model_supports_tools(model):
            if is_soc_triage_prompt(prompt):
                response = soc_response_with_ip_reputation(tool_results, prompt)
            else:
                _tool_name, result_payload = tool_result
                response = ip_reputation_tool_response(result_payload)
        elif model_supports_tools(model):
            tool_calls = select_tool_calls(tools, prompt)
            if tool_calls:
                time.sleep(self.processing_delay)
                stats = chat_stats(start_ns, prompt, "", is_tool_call=True)
                self._send_json(
                    200,
                    {
                        "model": model,
                        "created_at": utc_now(),
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": tool_calls,
                        },
                        "done": True,
                        "done_reason": "stop",
                        **stats,
                    },
                )
                return
            response = make_mock_response(model, prompt, messages)
        else:
            response = make_mock_response(model, prompt, messages)

        time.sleep(self.processing_delay)

        if stream:
            self._stream_chat(model, response, start_ns)
            return

        self._send_json(
            200,
            {
                "model": model,
                "created_at": utc_now(),
                "message": {
                    "role": "assistant",
                    "content": response,
                },
                "done": True,
                "done_reason": "stop",
                **chat_stats(start_ns, prompt, response, is_tool_result=has_tool_result),
            },
        )

    def _stream_chat(self, model: str, response: str, start_ns: int) -> None:
        self._start_jsonl_stream()
        count = 0
        for chunk in split_for_stream(response):
            count += 1
            self._write_jsonl(
                {
                    "model": model,
                    "created_at": utc_now(),
                    "message": {
                        "role": "assistant",
                        "content": chunk,
                    },
                    "done": False,
                }
            )
            time.sleep(self.stream_delay)

        self._write_jsonl(
            {
                "model": model,
                "created_at": utc_now(),
                "message": {
                    "role": "assistant",
                    "content": "",
                },
                "done": True,
                "done_reason": "stop",
                "total_duration": ns_since(start_ns),
                "load_duration": 1,
                "prompt_eval_count": 1,
                "prompt_eval_duration": 1,
                "eval_count": max(1, count),
                "eval_duration": 1,
            }
        )

    def _handle_show(self, body: dict[str, Any]) -> None:
        model = self._requested_model(body)
        if model is None:
            return
        config = MODEL_CATALOG[model]
        self._send_json(
            200,
            {
                "license": "proprietary",
                "modelfile": f"FROM {model}\nPARAMETER temperature 0\n",
                "parameters": "temperature 0",
                "template": "{{ .Prompt }}",
                "details": model_details(model),
                "model_info": {
                    "thm.general.architecture": config["architecture"],
                    "thm.general.file_type": 0,
                    "thm.context_length": 4096,
                },
            },
        )

    def _handle_legacy_embeddings(self, body: dict[str, Any]) -> None:
        model = self._requested_model(body)
        if model is None:
            return
        text = text_from_content(body.get("prompt"))
        self._send_json(200, {"embedding": embedding_for(text)})

    def _handle_embed(self, body: dict[str, Any]) -> None:
        start_ns = time.perf_counter_ns()
        model = self._requested_model(body)
        if model is None:
            return
        value = body.get("input", body.get("prompt", ""))
        inputs = value if isinstance(value, list) else [value]
        embeddings = [embedding_for(text_from_content(item)) for item in inputs]
        self._send_json(
            200,
            {
                "model": model,
                "embeddings": embeddings,
                "total_duration": ns_since(start_ns),
                "load_duration": 1,
                "prompt_eval_count": sum(max(1, len(text_from_content(item).split())) for item in inputs),
            },
        )

    def _handle_openai_chat(self, body: dict[str, Any]) -> None:
        start_ns = time.perf_counter_ns()
        model = self._requested_model(body)
        if model is None:
            return
        messages = body.get("messages", [])
        prompt = prompt_from_messages(messages)
        response = make_mock_response(model, prompt, messages)
        stream = bool(body.get("stream", False))
        time.sleep(self.processing_delay)

        if stream:
            self._stream_openai_chat(model, response)
            return

        self._send_json(
            200,
            {
                "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": response},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": max(1, len(prompt.split())),
                    "completion_tokens": max(1, len(response.split())),
                    "total_tokens": max(1, len(prompt.split()) + len(response.split())),
                },
                "total_duration_ns": ns_since(start_ns),
            },
        )

    def _stream_openai_chat(self, model: str, response: str) -> None:
        completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        self._start_sse_stream()
        self._write_sse(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
        )
        for chunk in split_for_stream(response):
            self._write_sse(
                {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": None}],
                }
            )
            time.sleep(self.stream_delay)
        self._write_sse(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
        )
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _handle_openai_completion(self, body: dict[str, Any]) -> None:
        model = self._requested_model(body)
        if model is None:
            return
        prompt = text_from_content(body.get("prompt"))
        response = make_mock_response(model, prompt)
        self._send_json(
            200,
            {
                "id": f"cmpl-{uuid.uuid4().hex[:24]}",
                "object": "text_completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{"text": response, "index": 0, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": max(1, len(prompt.split())),
                    "completion_tokens": max(1, len(response.split())),
                    "total_tokens": max(1, len(prompt.split()) + len(response.split())),
                },
            },
        )

    def _send_text(self, status: int, text: str) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _start_jsonl_stream(self) -> None:
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _write_jsonl(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        self.wfile.flush()

    def _start_sse_stream(self) -> None:
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _write_sse(self, payload: dict[str, Any]) -> None:
        self.wfile.write(b"data: " + json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n\n")
        self.wfile.flush()

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a tiny Ollama API server.")
    host = get_required_env("MOCK_OLLAMA_HOST")
    port = get_required_env("MOCK_OLLAMA_PORT")
    model = os.getenv("MOCK_OLLAMA_MODEL", "qwen2.5:1.5b")
    processing_delay_ms = get_required_env("MOCK_OLLAMA_PROCESSING_DELAY_MS")
    stream_delay_ms = get_required_env("MOCK_OLLAMA_STREAM_DELAY_MS")
    parser.add_argument("--host", default=host, help=f"host to bind, default: {host}")
    parser.add_argument("--port", type=int, default=int(port), help=f"port to bind, default: {port}")
    parser.add_argument("--model", default=model, help=f"model name, default: {model}")
    parser.add_argument(
        "--processing-delay-ms",
        type=int,
        default=int(processing_delay_ms),
        help=f"delay before returning a model response, default: {processing_delay_ms}",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=int(stream_delay_ms),
        help=f"delay between streamed chunks, default: {stream_delay_ms}",
    )
    return parser.parse_args()


def main() -> int:
    load_env()
    args = parse_args()
    if not is_supported_model(args.model):
        print(f"Error: model '{args.model}' not found. Available models: {', '.join(MODEL_CATALOG)}")
        return 1

    server = ThreadingHTTPServer((args.host, args.port), MockOllamaHandler)
    server.mock_model = args.model
    server.processing_delay = max(0, args.processing_delay_ms) / 1000
    server.stream_delay = max(0, args.delay_ms) / 1000

    def interrupt(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupt)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, interrupt)

    print(f"Ollama API listening on http://{args.host}:{args.port}")
    print(f"Model: {args.model}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Ollama server...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
