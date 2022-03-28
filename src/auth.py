import json
from os import access
import traceback
from flask import Blueprint, jsonify, request, redirect,url_for
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from datetime import datetime as dt
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT
from src.database import User as User, UserTokens
from src.database import Accounts as Accounts
from src.database import UserTokens as UserTokens
from src.database import db
import uuid
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token,get_jwt_identity, get_jwt, decode_token
from src.models import UserModel,UserLoginModel, UserResetPasswordModel, UserSetPasswordModel
from flask_pydantic import validate
from flask_mail import Message
from src.services.mail import mail
from src.services.jwt import jwt
from src.services.token import confirm_email_confirmation_token,generate_email_confirmation_token 
import random 
import string
from functools import wraps
from flask_cors import cross_origin

auth = Blueprint("auth",__name__,url_prefix="/api/v1/auth")

# decorater for access_level
def restricted(access_group):
    def decorator(func):
        @wraps(func)
        def wrapper_function(*args,**kwargs):
            print(access_group)
            user = get_jwt_identity()
            user = User.query.filter_by(guid=user).first()
            if(user.allowed(access_group)):
                return func(*args,**kwargs)
            else:
                return jsonify({
                    'error': 'Not enough permissions!'
                }),HTTP_403_FORBIDDEN
        return wrapper_function
    return decorator
    
# get user details
# @auth.get('/users')
# @validate()
# @cross_origin()
# def get_users():
#     user_id = request.args.get('user_id')
#     if(user_id):
#         user=User.query.filter_by(guid=user_id).first()
#         if(user):
#             return jsonify({
#                 'user': {
#                     'email': user.email
#                 }
#             })

    
#     return jsonify({
#         "error": "User not found"
#     }), HTTP_400_BAD_REQUEST

@auth.post('/signup')
@validate()
@cross_origin(origins="*")
def signup(body: UserModel):
    
    # data = request.json
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

@auth.route("/login",methods=["POST","OPTIONS"])
@validate()
@cross_origin(origin="*")
def login(body: UserLoginModel):
    email = body.email
    password = body.password

    user=User.query.filter_by(email=email).first()

    if user: 
        is_pass_correct = check_password_hash(user.password,password)
        if is_pass_correct:
            refresh_token = create_refresh_token(identity=user.guid)
            access_token  = create_access_token(identity=user.guid)
            access_jti = decode_token(access_token)['jti']
            refresh_jti = decode_token(refresh_token)['jti']
            new_token = UserTokens(access_jti,refresh_jti,user.guid)
            db.session.add(new_token)
            db.session.commit()
            return jsonify({
                'user':{
                    'refresh_token': refresh_token,
                    'access_token': access_token,
                    'email': user.email
                }
            }), HTTP_200_OK
    
    return jsonify({
        "error": "Wrong credentials"
    }), HTTP_401_UNAUTHORIZED


@auth.get("/current_user")
@jwt_required()
@cross_origin()
@restricted("admin")
def current_user():

    user = get_jwt_identity()
    user = User.query.filter_by(guid=user).first()
    # return {"user":"protected information"}
    return jsonify({
        "user": {
            "email": user.email
        }
    }), HTTP_200_OK

@auth.get("/token/refresh")
@jwt_required(refresh=True)
@cross_origin()
def get_refresh_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)
    access_jti = decode_token(access)['jti']
    # refresh_jti = decode_token(refresh_token)['jti']
    refresh_jti = get_jwt()['jti']
    new_token = UserTokens(access_jti,refresh_jti,identity)
    db.session.add(new_token)
    db.session.commit()
    
    return jsonify({
        'access_token': access,
    }), HTTP_200_OK


# token_in_blocklist_loader decorater called everytime to check if the token provided is blacklisted or not
@jwt.token_in_blocklist_loader
# @cross_origin()
def check_if_token_revoked(jwt_header, jwt_payload):
    print(jwt_header)
    print(jwt_payload)
    jti = jwt_payload["jti"]
    type = jwt_payload["type"]
    if(type != 'refresh'):
        token = db.session.query(UserTokens).filter_by(access_jti=jti).first()
        if(token):
            print(token)
            if(token.status == 0):
                return True 
            elif token.status == 1: 
                return False
        else: 
            return True
    elif(type == 'refresh'):
        token = db.session.query(UserTokens).filter_by(refresh_jti=jti).first()
        if(token):
            if(token.status == 0):
                return True
            elif token.status == 1:
                return False
        else:
            return True
    # return token is not None
# Marking the token as revoked after the session is logged out, forcing the user to login again
@auth.delete("/logout")
@jwt_required()
@cross_origin()
def logout():
    try:
        jti = get_jwt()['jti']
        user_id = get_jwt_identity()
        token = db.session.query(UserTokens).filter_by(user_id=user_id,access_jti=jti).first()
        print(f"UserToken:{token}")
        refresh_jti = token.refresh_jti
        if token:
            # revoke all tokens associated with this refresh token
            db.session.query(UserTokens).filter_by(user_id=user_id,refresh_jti=refresh_jti).update({UserTokens.status:0,UserTokens.updated_at:dt.now()},synchronize_session = False)
            db.session.commit()
            return jsonify({
                'message': 'Token Revoked'
            }), HTTP_200_OK

                
        else:
            return jsonify({
                'error': 'Token not found'
            }), HTTP_404_NOT_FOUND

        # db.session.add(UserTokens(jti=jti,user_id=user_id))
        # db.session.commit()
        return jsonify({
            'message': 'Token Revoked'
        }), HTTP_200_OK
    except Exception as error:
        print(error)
        return jsonify({
            'error': 'Error in revoking the token'
        }),HTTP_400_BAD_REQUEST


def send_mail():
    pass
@auth.post("/reset_password")
@validate()
@cross_origin()
def reset_password(body: UserResetPasswordModel):
    email = body.email
    user = User.query.filter_by(email=email).first()

    if user: 
        password_reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        user.password_reset_token = password_reset_token
        db.session.commit()

        # message = Message('Confirm Password Change', sender = 'test', recipients = [email])
        # message.body = "Hello,\nWe've received a request to reset your password. If you want to reset your password, click the link below and enter your new password\n http://127.0.0.1:5000/api/v1/auth/" + user.password_reset_token
        # mail.send(message)
        return jsonify({
            "message": f"Password reset token sent on email,http://127.0.0.1:5000/api/v1/auth/{user.password_reset_token}"
        }), HTTP_200_OK
    return jsonify({
        'error': 'User not found'
    }), HTTP_404_NOT_FOUND

@auth.post("/<string:password_reset_token>")
@validate()
@cross_origin()
def password_reset_token(body: UserSetPasswordModel,password_reset_token:str):
    user = User.query.filter_by(password_reset_token=password_reset_token).first()
    if user: 
        password = body.password 
        confirm_password = body.confirm_password
        if password == confirm_password:
            pwd_hash = generate_password_hash(password)
            user.password = pwd_hash
            user.password_reset_token = None
            db.session.commit()
            # deactivate all user_tokens till now for this user id
            db.session.query(UserTokens).filter_by(user_id=user.guid).update({UserTokens.status:0,UserTokens.updated_at:dt.now()},synchronize_session = False)
            db.session.commit()
            return jsonify({
                'message':'Password Reset Successful'
            }), HTTP_200_OK
        else: 
            return jsonify({
                'error': "Invalid Password"
            }), HTTP_400_BAD_REQUEST
    return jsonify({
        'error': 'User not found'
    }), HTTP_404_NOT_FOUND

@auth.get("/confirm/<string:email_confirmation_token>")
@validate()
@cross_origin()
def confirm_email(email_confirmation_token:str):
    try: 
        email = confirm_email_confirmation_token(email_confirmation_token)
    except: 
        return jsonify({
            'error': 'Confirmation token expired'
        }), HTTP_400_BAD_REQUEST
    user = User.query.filter_by(email=email).first()

    if user: 

        if user.onboarding == 2: 
            return jsonify({
                'message': 'Email confirmed already, Please login'
            }), HTTP_200_OK
        
        else: 
            user.onboarding = 2
            db.session.add(user)
            db.session.commit()
            return jsonify({
                'message': 'Email confirmed!'
            }), HTTP_200_OK
@auth.after_request
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    return response