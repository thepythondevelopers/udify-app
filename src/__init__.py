from distutils.debug import DEBUG
from flask import Flask 
import os 
from src.auth import auth
from src.database import db
from src.mail import mail
from flask_jwt_extended import JWTManager
from flask_mail import Mail
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
            MAIL_USE_SSL=True
        )
    else:
        app.config.from_mapping(test_config)
    
    db.app = app
    db.init_app(app)
    mail.init_app(app)
    JWTManager(app)

    app.register_blueprint(auth)
    return app