import json
import sys
import urllib.parse
import urllib.request

OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:1.5b"

ABUSEDB_CHECK_URL = "http://localhost:8080/api/v2/check"
ABUSEDB_API_KEY = "4f9c2a7d8e1b3c6f0a5d9e2c7b1a8f3d6c4e9b2a1f0d7c8e6b3a9d5f2c1e7a4"
ABUSEDB_MAX_AGE_DAYS = "90"

TOOL = {
    "type": "function",
    "function": {
        "name": "IPreputationchecker",
        "description": "Check IP reputation using the AbuseDB API.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IPv4 address to check.",
                }
            },
            "required": ["ip"],
        },
    },
}

def call_ollama(messages):
    """Sends the conversation history (and tools) to the AI."""
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "tools": [TOOL], 
        "stream": False,
    }

    req = urllib.request.Request(
        OLLAMA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def call_abusedb(ip):
    """Sends an IP to AbuseDB to get its reputation score."""
    query_params = {"ipAddress": ip, "maxAgeInDays": ABUSEDB_MAX_AGE_DAYS}
    query_string = urllib.parse.urlencode(query_params) + "&verbose"

    req = urllib.request.Request(
        f"{ABUSEDB_CHECK_URL}?{query_string}",
        headers={"Key": ABUSEDB_API_KEY, "Accept": "application/json"},
    )

    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def run_react_loop(alert_content):
    system_prompt = "You are a SOC Triage Assistant. Analyze the provided JSON alert and output a triage summary in json format with exactly these four sections for each alert: 1.Log Id 2. Severity Guess: (e.g., Low, Medium, High, Critical) 3. Meaning: (What the alert probably indicates) 4. Suggested Next Step: (What the analyst should do next)"

    messages = [
        {
            "role": "user",
            "content": system_prompt + "\n\n" + alert_content,
        }
    ]

    while True:
        print("[*] Asking AI to analyze the data...")
        result = call_ollama(messages)
        assistant_message = result["message"]
        
        tool_calls = assistant_message.get("tool_calls", [])

        if not tool_calls:
            print("[*] AI returned final answer.")
            return assistant_message["content"]

        print(f"[*] AI requested {len(tool_calls)} tool call(s).")
        
        messages.append(assistant_message)

        for tool_call in tool_calls:
            tool_name = tool_call["function"]["name"]
            
            arguments = tool_call["function"]["arguments"]
            ip = arguments.get("ip", {}).get("value") if isinstance(arguments.get("ip"), dict) else arguments.get("ip")

            print(f"[*] Running Tool: {tool_name} on IP: {ip}")
            
            tool_result = call_abusedb(ip)
            
            messages.append(
                {
                    "role": "tool",
                    "name": tool_name,
                    "content": json.dumps(tool_result),
                }
            )

if __name__ == "__main__":
    file_path = sys.argv[1]
    
    with open(file_path, "r", encoding="utf-8") as f:
        alert_data = f.read()

    summary = run_react_loop(alert_data)
    
    print("\n--- FINAL TRIAGE SUMMARY ---")
    print(summary)