from flask import Flask,jsonify, current_app, request
import os 
import json
from werkzeug.security import check_password_hash
from flask_pydantic import validate
from database import db,User,Accounts
from flask_caching import Cache
# from pydantic_models import UserLoginModel
from datetime import datetime as dt, timedelta,timezone
from constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT
import validators
from itsdangerous import base64_decode
import jwt

DB_HOST = os.environ.get('DATABASE_HOST',"127.0.0.1")
DB_USER = os.environ.get('DATABASE_USER',"root")
DB_PORT = os.environ.get('DATABASE_PORT',3306)
DATABASE = os.environ.get('DATABASE_NAME',"udify")
DB_PASSWORD = os.environ.get('DATABASE_PASSWORD',"root")
cache = Cache()

app = Flask(__name__)
app.config.update(
            SECRET_KEY = os.environ.get("SECRET_KEY","dfdas143-fddsfb3@4rfv"),
            SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DATABASE}",
            SQLALCHEMY_TRACK_MODIFICATIONS = False,
            # SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
            MAIL_SERVER=os.environ.get("MAIL_SERVER",""),
            MAIL_PORT=os.environ.get("MAIL_PORT",""),
            MAIL_USERNAME=os.environ.get("MAIL_USERNAME",""),
            MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD",""),
            MAIL_USE_TLS=False,
            MAIL_USE_SSL=True,
            SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT","1b4K11!"),
            CACHE_TYPE='redis',
            CACHE_KEY_PREFIX='server1',
            CACHE_REDIS_HOST=' http://udify-redis-do-user-4912141-0.b.db.ondigitalocean.com',
            CACHE_REDIS_PORT='25061',
            CACHE_REDIS_URL=f'rediss://default:AVNS_H1ldRswWtOxMWL-@udify-redis-do-user-4912141-0.b.db.ondigitalocean.com:25061',
            # CACHE_REDIS_PASSWORD='AVNS_H1ldRswWtOxMWL-'            
)

db.app = app
db.init_app(app)
cache.init_app(app)

def is_jwt_authorized(jwt_access_token):
    '''

    To check if the jwt shared is authorized or not
    @params: a jwt access token 
    @returns: True if valid token is valid

    '''
    jwt_access_token = jwt_access_token.split(" ")
    if(len(jwt_access_token) != 2):
        print("Incorrect Format")
        return False
    if(jwt_access_token[0] != "Bearer"):
        print("Not a Bearer Token")
        return False
    # get the actual jwt
    jwt_access_token = jwt_access_token[1]
    print(f"Token: {jwt_access_token}")
    token_header = jwt_access_token.split(".")[0]
    token_content = jwt_access_token.split(".")[1]
    token_signature = jwt_access_token.split(".")[2]
    token_header =json.loads(base64_decode(token_header))
    print(token_header)
    
    # prevent unsigned tokens
    if(token_header['alg'] == "none"):
        return False
    try: 
        decoded = jwt.decode(jwt_access_token,key=current_app.config["SECRET_KEY"],algorithms="HS256")
    except Exception as error: 
        print(error)
        return False
    return True    

def is_jwt_valid(jwt_access_token):
    
    '''
    Checks whether this token has been created from an invalid token or not
    @params: jwt_access_token
    @returns: true if valid token

    '''
    jwt_payload = jwt.decode(jwt_access_token,key=current_app.config["SECRET_KEY"],algorithms="HS256")
    user_id = jwt_payload["user_id"]
    exp = jwt_payload["exp"]
    print("Time before which invalid" + str(cache.get(user_id)))
    print(dt.fromtimestamp(exp))
    return cache.get(user_id) == None or cache.get(user_id) < dt.fromtimestamp(exp,tz=timezone.utc) 


@app.route("/", methods=["POST"])
def current_user():
    if(request.headers.get('Authorization') == None):
        return jsonify({
            "error": "Authentication Token missing"
        }),HTTP_401_UNAUTHORIZED
    if(is_jwt_authorized(request.headers.get('Authorization')) == False):
        return jsonify({
            "error":"Invalid Token"
        }), HTTP_401_UNAUTHORIZED
    
    if(is_jwt_valid(request.headers.get('Authorization').split(" ")[1]) ==  False):
        return jsonify({
            "error": "Invalid Token"
        }), HTTP_401_UNAUTHORIZED
    
    user_id = jwt.decode(request.headers.get('Authorization').split(' ')[1],key=current_app.config["SECRET_KEY"],algorithms="HS256")['user_id']
    user = User.query.filter_by(guid=user_id).first()
    # return {"user":"protected information"}
    return jsonify({
        "user": {
            "email": user.email
        }
    }), HTTP_200_OK


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True,port=80)