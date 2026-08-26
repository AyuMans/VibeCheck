import requests


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

MODEL_NAME = "qwen2.5-coder:3b"


def ask_ollama(
    prompt: str,
    format_schema: dict | None = None
) -> str:

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,

            # Limits how many tokens the AI can generate.
            # Our review output should not be extremely long.
            "num_predict": 1200,

            # Keep context limited so very long code does not
            # make inference unnecessarily slow.
            "num_ctx": 8192,

            # Use CPU threads efficiently.
            "num_thread": 4
        }
    }

    if format_schema is not None:
        payload["format"] = format_schema

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        return data["response"]

    except requests.exceptions.Timeout:

        raise RuntimeError(
            "AI review timed out after 120 seconds."
        )

    except requests.exceptions.ConnectionError:

        raise RuntimeError(
            "Could not connect to Ollama. "
            "Make sure Ollama is running."
        )