from backend.ollama_client import ask_ollama


prompt = "In one sentence, explain what FastAPI is."

answer = ask_ollama(prompt)

print(answer)