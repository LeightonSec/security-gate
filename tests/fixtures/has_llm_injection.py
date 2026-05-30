"""Dirty fixture for LlmInjectionScanner — request input flows directly into LLM call."""
import anthropic
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/chat", methods=["POST"])
def chat():
    user_prompt = request.get_json().get("prompt")
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return {"response": response.content[0].text}
