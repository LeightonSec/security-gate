"""Dirty fixture for CmdInjectionScanner — all three violation types present."""
import os
import subprocess


# CRITICAL: eval with variable argument
def run_code(user_code):
    return eval(user_code)


# CRITICAL: exec with f-string (variable interpolation)
def execute_template(template, value):
    exec(f"result = {template}")


# CRITICAL: os.system with variable
def run_command(cmd):
    os.system(cmd)


# CRITICAL: subprocess with shell=True
def run_shell(command):
    subprocess.run(command, shell=True)
