import json
import sys
import urllib.parse
import urllib.request

OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:1.5b"

ABUSEDB_CHECK_URL = "http://localhost:8080/api/v2/check"
ABUSEDB_API_KEY = "4f9c2a7d8e1b3c6f0a5d9e2c7b1a8f3d6c4e9b2a1f0d7c8e6b3a9d5f2c1e7a4"
ABUSEDB_MAX_AGE_DAYS = "90"

TOOL = 

def call_ollama(messages):
    """Sends the conversation history (and tools) to the AI."""
    payload = {
        
    }

    req = urllib.request.Request(
        OLLAMA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))

def run_react_loop(alert_content):
    system_prompt = ""

    messages = [
        {
            "role": "user",
            "content": system_prompt + "\n\n" + alert_content,
        }
    ]

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

if __name__ == "__main__":
    file_path = sys.argv[1]
    
    with open(file_path, "r", encoding="utf-8") as f:
        alert_data = f.read()

    summary = run_react_loop(alert_data)
    
    print(summary)
