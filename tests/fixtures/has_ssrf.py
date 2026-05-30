"""Dirty fixture for SsrfScanner — user-controlled URLs passed to HTTP clients."""
import urllib.request

import httpx
import requests


# CRITICAL: requests.get with variable URL
def fetch_user_url(url):
    return requests.get(url)


# CRITICAL: httpx with f-string URL
def fetch_resource(host):
    return httpx.get(f"http://{host}/data")


# CRITICAL: urllib with variable
def open_target(target):
    return urllib.request.urlopen(target)
