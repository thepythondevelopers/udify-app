from distutils.debug import DEBUG
from flask import Flask 
import os 
from src.auth import auth
from src.database import db
from src.services.mail import mail
from src.services.jwt import jwt
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from src.services.cors import cors

def create_app(test_config=None):
    
    app = Flask(__name__,instance_relative_config=True)

    if(test_config is None):

        app.config.from_mapping(
            SECRET_KEY = os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:root@127.0.0.1:3306/udify",
            SQLALCHEMY_TRACK_MODIFICATIONS = False,
            JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
            MAIL_SERVER=os.environ.get("MAIL_SERVER"),
            MAIL_PORT=os.environ.get("MAIL_PORT"),
            MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
            MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
            MAIL_USE_TLS=False,
            MAIL_USE_SSL=True,
            SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT"),
            CORS_HEADERS='Content-Type'
        )
    else:
        app.config.from_mapping(test_config)
    
    db.app = app
    db.init_app(app)
    mail.init_app(app)
    # jwt = JWTManager(app)
    jwt.init_app(app)
    # cors.init_app(app,resources={r'/*': {'origins': '*'}})
    cors.init_app(app, resources={r"*": {"origins": "*"}})

    app.register_blueprint(auth)
    return app
    