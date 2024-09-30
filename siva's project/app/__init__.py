from flask import Flask
from app.extensions import db, csrf, jwt, login_manager, blacklist
from app.auth import auth_bp
from app.users import users_bp

def create_app():
    app = Flask(__name__)
    
    # Configure app
    app.config.from_object('config.Config')  # Ensure this path is correct

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)

    return app
