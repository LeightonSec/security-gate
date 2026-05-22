# Synthetic fixture — should produce zero findings
import os
from pydantic import BaseModel

SECRET_KEY = os.environ['SECRET_KEY']  # required, no fallback

class InputSchema(BaseModel):
    name: str
    value: int

def process(raw: dict) -> InputSchema:
    return InputSchema(**raw)
