"""Dirty fixture for AiMlScanner — all three violation types present."""

import os

from transformers import AutoModel, AutoTokenizer

# HIGH: from_pretrained without revision=
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

# CRITICAL: trust_remote_code=True (also HIGH for missing revision=)
model = AutoModel.from_pretrained("custom/model", trust_remote_code=True)

# MEDIUM: telemetry explicitly set permissive
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "0"
