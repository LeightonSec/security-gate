# Synthetic fixture — triggers path_manipulation scanner
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'other-repo')))
sys.path.append('/tmp/injected')

