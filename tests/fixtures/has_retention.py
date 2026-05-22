# Synthetic fixture — triggers retention_policy scanner
import sqlite3

def log_event(data):
    with sqlite3.connect('events.db') as conn:
        conn.execute('INSERT INTO events (data) VALUES (?)', (data,))
        conn.commit()

def store_json(data):
    import json
    with open('log.json', 'a') as f:
        f.write(json.dumps(data) + '\n')
