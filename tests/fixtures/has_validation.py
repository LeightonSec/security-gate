# Synthetic fixture — triggers missing_validation scanner
from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    data = request.get_json()
    name = data['name']
    return {'ok': True}

@app.route('/query')
def query():
    q = request.args.get('q')
    return {'result': q}
