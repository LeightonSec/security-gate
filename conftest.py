from pathlib import Path
import sys

# Add project root to sys.path for local dev without `pip install -e .`
# Note: security-gate scan will flag this — it's a known low-risk test tooling pattern.
sys.path.insert(0, str(Path(__file__).parent))
