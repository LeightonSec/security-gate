"""Dirty fixture for WebAppScanner — all four violation types present."""

from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)

# HIGH: debug mode enabled
app.debug = True

# HIGH: CORS wildcard
CORS(app)


# CRITICAL: SQL injection via f-string
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


# CRITICAL: SQL injection via concatenation
def search_users(name):
    import sqlite3
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()


# MEDIUM: POST route without auth decorator
@app.route("/admin/delete", methods=["POST", "DELETE"])
def delete_user():
    user_id = request.json.get("id")
    return {"deleted": user_id}
