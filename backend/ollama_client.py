import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

MODEL_NAME = "qwen2.5-coder:3b"


def ask_ollama(prompt: str, format_schema: dict | None = None) -> str:

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0
        }
    }

    if format_schema is not None:
        payload["format"] = format_schema

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=300
    )

    response.raise_for_status()

    data = response.json()

    return data["response"]