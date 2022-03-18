import json
from flask import Blueprint, jsonify, request, redirect,url_for
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from src.constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT
from src.database import User as User
from src.database import Accounts as Accounts
from src.database import db
import uuid
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token,get_jwt_identity
from src.models import UserModel,UserLoginModel, UserResetPasswordModel, UserSetPasswordModel
from flask_pydantic import validate
from flask_mail import Message
from src.mail import mail
import random 
import string

auth = Blueprint("auth",__name__,url_prefix="/api/v1/auth")

@auth.post('/signup')
@validate()
def signup(body: UserModel):
    
    # data = request.json
    first_name = body.first_name
    last_name  = body.last_name
    email      = body.email
    password   = body.password
    
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
    new_account = Accounts(accid)
    new_user = User(first_name,last_name,accid,email, pwd_hash)
    db.session.add(new_account)
    db.session.commit()
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User created",
        "user": {
            "email": email,
            "first_name": first_name
        }
    }), HTTP_201_CREATED

@auth.post("/login")
@validate()
def login(body: UserLoginModel):
    email = body.email
    password = body.password

    user=User.query.filter_by(email=email).first()

    if user: 
        is_pass_correct = check_password_hash(user.password,password)
        if is_pass_correct:
            refresh_token = create_refresh_token(identity=user.guid)
            access_token  = create_access_token(identity=user.guid)

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

# @auth.post("/create_user")
# @jwt_required()
# def create_user():
#     data = request.json
#     user = get_jwt_identity()
#     user = User.query.filter_by(guid=user).first()
#     if user.access_group == "admin" or user.access_group == "owner": 
#         account_id = request.args.get(account_id)

#         account = Accounts.query.filter_by(guid=account_id).first()
#         if account: 
#             first_name = data["first_name"]
#             last_name  = data["last_name"]
#             email      = data["email"]

@auth.get("/current_user")
@jwt_required()
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
def get_refresh_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)

    return jsonify({
        'access_token': access 
    }), HTTP_200_OK

@auth.get("/logout")
@jwt_required()
def logout():
    user = get_jwt_identity()
    user = User.query.filter_by(guid=user).first()

def send_mail():
    pass
@auth.post("/reset_password")
@validate()
def reset_password(body: UserResetPasswordModel):
    email = body.email
    user = User.query.filter_by(email=email).first()

    if user: 
        password_reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        user.password_reset_token = password_reset_token
        db.session.commit()

        message = Message('Confirm Password Change', sender = 'yasver3474@gmail.com', recipients = [email])
        message.body = "Hello,\nWe've received a request to reset your password. If you want to reset your password, click the link below and enter your new password\n http://127.0.0.1:5000/api/v1/auth/" + user.password_reset_token
        mail.send(message)
        return jsonify({
            "message": "Password reset token sent on email"
        }), HTTP_200_OK
    return jsonify({
        'error': 'User not found'
    }), HTTP_404_NOT_FOUND

@auth.post("/<string:password_reset_token>")
@validate()
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
