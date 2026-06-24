"""Dirty fixture for SstiScanner — both violation types present."""
import jinja2
from flask import render_template_string


# CRITICAL: render_template_string with variable argument
def render_greeting(user_input):
    return render_template_string(user_input)


# CRITICAL: jinja2.Template with variable argument
def render_dynamic(template_str):
    tmpl = jinja2.Template(template_str)
    return tmpl.render()
