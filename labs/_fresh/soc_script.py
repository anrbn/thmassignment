import json
import sys
import urllib.request

# STEP 1: Fill in the OLLAMA_CHAT_URL and the OLLAMA_MODEL
OLLAMA_CHAT_URL = ""
OLLAMA_MODEL = ""

# STEP 2: The Prompt
def call_ollama(alert_content):
    system_prompt =

# STEP 3: Fill in required 
    payload = {
        "model": <FILL-IT>,
        "messages": [
            {
                "role": "user",
                "content": system_prompt + "\n\n" + alert_content,
            }
        ],
        "stream": <FILL-IT>,
    }

    # STEP 4: Prepare the web request


    # STEP 5: Send the request and read the response


if __name__ == "__main__":
    file_path = sys.argv[1]
    
    with open(file_path, "r", encoding="utf-8") as f:
        alert_data = f.read()

    # STEP 6: Call Ollama and Print Results
    summary = call_ollama(<FILL-IT>)
    print(summary)
