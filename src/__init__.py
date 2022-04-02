from distutils.debug import DEBUG
from flask import Flask 
import os 
from src.auth import auth
from src.database import db
from src.util.mail import mail
from src.util.jwt import jwt
from src.util.cache import cache
from flask_jwt_extended import JWTManager
from flask_mail import Mail
# from flask

DB_HOST = os.environ.get('DATABASE_HOST')
DB_USER = os.environ.get('DATABASE_USER')
DB_PORT = os.environ.get('DATABASE_PORT')
DATABASE = os.environ.get('DATABASE_NAME')
DB_PASSWORD = os.environ.get('DATABASE_PASSWORD')

def create_app(test_config=None):
    
    app = Flask(__name__,instance_relative_config=True)

    if(test_config is None):

        app.config.from_mapping(
            SECRET_KEY = os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DATABASE}",
            SQLALCHEMY_TRACK_MODIFICATIONS = False,
            # SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
            MAIL_SERVER=os.environ.get("MAIL_SERVER",""),
            MAIL_PORT=os.environ.get("MAIL_PORT",""),
            MAIL_USERNAME=os.environ.get("MAIL_USERNAME",""),
            MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD",""),
            MAIL_USE_TLS=False,
            MAIL_USE_SSL=True,
            SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT","1b4K11!")
            # CACHE_TYPE='redis',
            # CACHE_KEY_PREFIX='server1',
            # CACHE_REDIS_HOST='localhost',
            # CACHE_REDIS_PORT='6379',
            # CACHE_REDIS_URL='redis://localhost:6379'
        )
    else:
        app.config.from_mapping(test_config)
    
    db.app = app
    db.init_app(app)
    # mail.init_app(app)
    # jwt = JWTManager(app)
    # jwt.init_app(app)
    # cache.init_app(app)

    app.register_blueprint(auth)
    return app
    