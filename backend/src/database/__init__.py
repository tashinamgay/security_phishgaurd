# backend/src/database/__init__.py
# MongoDB connection setup - shared across the whole app
# Member: Tashi
#
# SIMPLE EXPLANATION:
# PyMongo connects Flask to MongoDB Atlas (online database)
# Use get_db() anywhere in the code to access the database
# Example: db = get_db()  then  db.users.find_one({'username': 'tashi'})

from flask_pymongo import PyMongo

mongo = PyMongo()  # MongoDB connection - shared across app


def get_db():
    """Return MongoDB database. Use this in all routes."""
    return mongo.db
