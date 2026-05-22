# Synthetic fixture — triggers hardcoded_secrets scanner
import os

SECRET_KEY = os.getenv('SECRET_KEY', 'changeme')
API_KEY = 'hardcoded-key-value-that-is-long-enough'

def get_config():
    return {
        "secret": SECRET_KEY,
        "key": API_KEY,
    }
