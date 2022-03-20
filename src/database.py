from flask_sqlalchemy import SQLAlchemy
from datetime import datetime as dt
import uuid 
import os


db = SQLAlchemy()
class Accounts(db.Model):
    __tablename__   = "accounts"
    guid            = db.Column(db.String(32),primary_key = True)
    created_at      = db.Column(db.DateTime)
    name            = db.Column(db.String(255))
    api_token       = db.Column(db.String(32))
    public_id       = db.Column(db.String(5))
    address_street  = db.Column(db.String(255))
    address_unit    = db.Column(db.String(255))
    address_city    = db.Column(db.String(255))
    address_state   = db.Column(db.String(2))
    address_zip     = db.Column(db.String(255))
    address_country = db.Column(db.String(255))
    users = db.relationship("User", backref = 'accounts')

    def __init__(self,accid,**kwargs):
        self.guid       = accid
        self.created_at = dt.now()
        api_uuid = uuid.uuid4()
        api_uuid = str(api_uuid)
        api_uuid = api_uuid.replace("-","")
        self.api_token          = api_uuid
        self.name               = kwargs.get('name', "TEST")
        self.public_id          = kwargs.get('public_id', "TEST")
        self.address_state      = kwargs.get('address_state',"CA")
        self.address_city       = kwargs.get("address_city","CA")
        self.address_zip        = kwargs.get("address_zip","123456")
        self.address_country    = kwargs.get("address_country", "US")
        self.address_unit       = kwargs.get("address_unit", "US")
        self.address_street     = kwargs.get("address_street", "STREET-1")

class User(db.Model):
    __tablename__ = "users"
    guid        = db.Column(db.String(32), primary_key = True)
    first_name  = db.Column(db.String(255))
    last_name   = db.Column(db.String(255))
    email       = db.Column(db.String(255))
    password    = db.Column(db.Text)
    created_at  = db.Column(db.DateTime)
    account_id  = db.Column(db.String(32), db.ForeignKey('accounts.guid'))
    onboarding  = db.Column(db.Integer)
    password_reset_token = db.Column(db.String(32))

    def __init__(self,first_name,last_name,account_id,email,password):
        user_id = uuid.uuid4()
        user_id = str(user_id)
        user_id = user_id.replace("-","")
        self.guid       = uuid.UUID(user_id).hex
        self.first_name = first_name 
        self.last_name  = last_name
        self.account_id = account_id
        self.email      = email 
        self.password   = password
        self.created_at = dt.now()
        self.onboarding = 0
    
    def __repr__(self) -> str:
        return f"{self.guid} - {self.first_name}"

# To store the blocklisted tokens, so that access from those tokens is prevented
class UserTokens(db.Model):
    __tablename__ = "user_tokens"
    guid              = db.Column(db.String(32), primary_key = True)
    access_jti        = db.Column(db.String(36))
    refresh_jti       = db.Column(db.String(36))    
    created_at        = db.Column(db.DateTime)
    updated_at        = db.Column(db.DateTime)
    user_id           = db.Column(db.String(32))
    status            = db.Column(db.Boolean)

    def __init__(self,access_jti,refresh_jti,user_id):
        guid = uuid.uuid4()
        guid = str(guid)
        # self.guid = guid 
        guid = guid.replace("-","")
        self.guid        = guid
        self.access_jti  = access_jti
        self.refresh_jti = refresh_jti
        self.user_id     = user_id
        self.status      = True
        self.created_at  = dt.now()
    
    def __repr__(self) -> str: 
        return f"{self.guid} - {self.access_jti}"
    