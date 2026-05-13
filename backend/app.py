# backend/app.py
# Main Flask application entry point
# Run this file to start PhishGuard: python app.py

import os
from flask import Flask
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from bson import ObjectId
from src.database import mongo
from src.auth.user_model import MongoUser

load_dotenv()

bcrypt        = Bcrypt()
csrf          = CSRFProtect()
login_manager = LoginManager()


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join('..', 'frontend', 'templates'),
        static_folder=os.path.join('..', 'frontend', 'static'),
    )
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-change-me')
    mongo_uri = os.getenv('MONGO_URI', '')
    if not mongo_uri:
        raise RuntimeError("\n❌ MONGO_URI not set! Copy .env.example to .env\n")
    app.config['MONGO_URI'] = mongo_uri
    # 16MB upload limit — needed for ML dataset CSV uploads
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    # Disable CSRF for API testing with Postman
    app.config['WTF_CSRF_ENABLED'] = False

    mongo.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    from src.auth.routes import auth_bp
    from src.dashboard.routes import dashboard_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    return app


@login_manager.user_loader
def load_user(user_id):
    try:
        doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        return MongoUser(doc) if doc else None
    except Exception:
        return None


if __name__ == '__main__':
    app = create_app()
    print("\n🛡️  PhishGuard starting...")
    print("📡  Connecting to MongoDB Atlas...")
    print("🌐  Open your browser at: http://localhost:5000\n")
    app.run(debug=True)