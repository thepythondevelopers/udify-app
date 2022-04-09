from flask import Flask,jsonify, current_app
import os 
import json
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pydantic import validate
from database import db,User,Accounts
from flask_caching import Cache
from pydantic_models import UserModel
from constants.http_status_codes import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT
import validators
from itsdangerous import URLSafeTimedSerializer
import uuid


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

def generate_email_confirmation_token(email):

    serilalizer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    print(f"Serial dumps: {serilalizer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])}")
    return serilalizer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])


@app.route("/", methods=["POST"])
@validate()
def signup(body: UserModel):
    first_name = body.first_name
    last_name  = body.last_name
    email      = body.email
    password   = body.password

    # Optional Fields
    address_state   = body.address_state if body.address_state is not None else "CA"
    address_city    = body.address_city if body.address_city is not None else "CA"
    address_zip     = body.address_zip if body.address_zip is not None else "123456"
    address_country = body.address_country if body.address_country is not None else "US"
    address_unit    = body.address_unit if body.address_unit is not None else "US"
    address_street  = body.address_street if body.address_unit is not None else "Default"
    
    if len(password) < 6:
        return jsonify({'error':f'Password too short'}), HTTP_400_BAD_REQUEST
        
    if not validators.email(email):
        return jsonify({'error':'Email is not valid'}), HTTP_400_BAD_REQUEST
    
    if db.session.query(User).filter_by(email=email).first() is not None:
        return jsonify({'error':'Account exists!'}), HTTP_409_CONFLICT
    
    pwd_hash = generate_password_hash(password)

    accid = uuid.uuid4()
    accid = str(accid)
    accid = accid.replace("-","")
    # Create account and check for the address filed 
    # /!\ need to validate the public_id field
    new_account = Accounts(accid,address_state=address_state,address_city=address_city,address_zip=address_zip,address_country=address_country,address_unit=address_unit,address_street=address_street)
    new_user = User(first_name,last_name,accid,email, pwd_hash)
    db.session.add(new_account)
    db.session.commit()
    db.session.add(new_user)
    db.session.commit()

    # message = Message('Verify your Email Address', sender = 'test', recipients = [email])
    token = generate_email_confirmation_token(email)
    # message.body = "Hello,\Welcome to Udify!, click the link below to verify your email address\n http://127.0.0.1:5000/api/v1/auth/" + token
    # mail.send(message)

    return jsonify({
        "message": f"User created, Hello,\Welcome to Udify!, click the link below to verify your email address\n http://127.0.0.1:5000/api/v1/auth/confirm/{token}",
        "user": {
            "email": email,
            "first_name": first_name
        }
    }), HTTP_201_CREATED 


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)