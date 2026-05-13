# backend/setup.py
# Run this to check your setup is correct before running the app
# Usage: python setup.py

import os, sys
from dotenv import load_dotenv

load_dotenv()

print("\n🛡️  PhishGuard Setup Checker")
print("=" * 40)

# Check .env exists
if not os.path.exists('.env'):
    print("❌ .env file NOT found!")
    print("   Run: copy .env.example .env")
    print("   Then add your MongoDB Atlas URI")
    sys.exit(1)
print("✅ .env file found")

# Check MONGO_URI
uri = os.getenv('MONGO_URI', '')
if not uri or 'YOUR_USERNAME' in uri:
    print("❌ MONGO_URI not set properly in .env!")
    print("   Add your MongoDB Atlas connection string")
    sys.exit(1)
if 'mongodb+srv' in uri:
    print("✅ MongoDB Atlas URI detected (cloud)")
elif 'localhost' in uri:
    print("⚠️  Local MongoDB URI detected — use Atlas for team sharing")
else:
    print("✅ MONGO_URI set")

# Check SECRET_KEY
key = os.getenv('SECRET_KEY', '')
if not key or key == 'change-this-to-a-long-random-string':
    print("⚠️  SECRET_KEY not changed — update it in .env")
else:
    print("✅ SECRET_KEY set")

# Check OpenAI
oai = os.getenv('OPENAI_API_KEY', '')
if not oai or oai == 'your-openai-api-key-here':
    print("⚠️  OPENAI_API_KEY not set — AI explanation will use fallback (still works!)")
else:
    print("✅ OpenAI API key set")

# Test MongoDB connection
print("\n📡 Testing MongoDB Atlas connection...")
try:
    from pymongo import MongoClient
    from pymongo.server_api import ServerApi
    client = MongoClient(uri, server_api=ServerApi('1'), serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ MongoDB Atlas connected successfully!\n")
    print("🚀 Everything looks good! Run: python app.py")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    print("\nFixes to try:")
    print("  1. Check your URI in .env")
    print("  2. Atlas → Network Access → Add 0.0.0.0/0")
    print("  3. Check username and password are correct")
    sys.exit(1)
