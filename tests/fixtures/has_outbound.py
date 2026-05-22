# Synthetic fixture — triggers outbound_calls scanner
import requests
from anthropic import Anthropic

client = Anthropic(api_key="test")

def fetch_data(url):
    return requests.get(url).json()

def call_llm(prompt):
    return client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=100, messages=[{"role": "user", "content": prompt}])
