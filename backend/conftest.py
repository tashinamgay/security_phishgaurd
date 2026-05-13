# conftest.py
# Tells pytest where to find the app modules
import sys
import os

# Add backend folder to Python path
sys.path.insert(0, os.path.dirname(__file__))