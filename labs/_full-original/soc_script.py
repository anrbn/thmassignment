import json
import sys
import urllib.request

OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:1.5b"

def call_ollama(alert_content):
    system_prompt = "You are a SOC Triage Assistant. Analyze the provided JSON alert and output a triage summary in json format with exactly these four sections for each alert: 1.Log Id 2. Severity Guess: (e.g., Low, Medium, High, Critical) 3. Meaning: (What the alert probably indicates) 4. Suggested Next Step: (What the analyst should do next)"

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "user",
                "content": system_prompt + "\n\n" + alert_content,
            }
        ],
        "stream": False,
    }

    req = urllib.request.Request(
        OLLAMA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode("utf-8"))
        return result["message"]["content"]

if __name__ == "__main__":
    file_path = sys.argv[1]
    
    with open(file_path, "r", encoding="utf-8") as f:
        alert_data = f.read()

    summary = call_ollama(alert_data)
    print(summary)