"""Put pi-server/ on sys.path so tests can ``import thermostat`` regardless of
pytest's rootdir. Harmless to the existing ast-based tests, which resolve the
server source by absolute path and don't rely on the import path.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
