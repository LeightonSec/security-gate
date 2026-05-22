# Synthetic fixture — triggers path_manipulation scanner
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'other-repo')))
sys.path.append('/tmp/injected')

from detector import analyse_prompt
