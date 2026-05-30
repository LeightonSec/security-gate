# Dirty fixture for SemgrepScanner — multi-hop taint chains that regex scanners miss.
#
# The llm_injection regex scanner tracks variables directly assigned from request.*
# It loses track at reassignment: once a variable is assigned from another variable
# (not directly from request.*), it falls out of the tainted set.
#
# The functions below use 2-hop chains the regex scanner cannot follow but
# semgrep's AST-based taint analysis can (within the same function body).
import anthropic
import requests
from flask import Flask, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/chat", methods=["POST"])
def chat_multihop():
    # 2-hop: request → data → (dict access) → prompt → (reassignment) → user_message → LLM
    # Regex scanner: data is tainted, but user_message never assigned from request.* directly
    data = request.get_json()
    prompt = data.get("message")
    user_message = prompt  # regex scanner loses track here — user_message not in tainted set
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_message}],
    )
    return {"response": response.content[0].text}


@app.route("/fetch", methods=["POST"])
def fetch_multihop():
    # 2-hop: request → target → (reassignment) → url → HTTP client
    target = request.get_json().get("url")
    url = target  # regex scanner loses track here
    return requests.get(url).text
