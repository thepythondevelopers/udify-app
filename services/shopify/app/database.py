from flask_sqlalchemy import SQLAlchemy
from datetime import datetime as dt
import uuid 
import os
import enum 

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
    integrations = db.relationship("Integrations", backref = 'accounts')

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

class Integrations(db.Model):
    __tablename__ = "integrations"
    guid               = db.Column(db.String(32), primary_key = True)
    store_api_key      = db.Column(db.String(32))
    store_api_secret   = db.Column(db.String(42))
    domain             = db.Column(db.String(255))
    created_at          = db.Column(db.DateTime)
    account_id      = db.Column(db.String(32), db.ForeignKey('accounts.guid'))
    store_id        = db.Column(db.String(32), db.ForeignKey('stores.guid'))

    def __init__(self,store_api_key,store_api_secret,domain,account_id,store_id):
        integration_id = uuid.uuid4()
        integration_id = str(integration_id)
        integration_id = integration_id.replace("-","")
        self.guid       = uuid.UUID(integration_id).hex
        self.store_api_key = store_api_key 
        self.store_api_secret  = store_api_secret
        self.domain = domain
        self.account_id      = account_id 
        self.store_id = store_id
        self.created_at = dt.now()
        
    def __repr__(self) -> str:
        return f"{self.guid} - {self.first_name}"


class Stores(db.Model):
    __tablename__ = "stores"

    guid    = db.Column(db.String(32), primary_key = True)
    domain  = db.Column(db.String(255))
    stores = db.relationship("Integrations", backref = 'stores')

    def __init__(self, domain):
        self.domain = domain
        store_id = uuid.uuid4()
        store_id = str(store_id)
        store_id = store_id.replace("-","")
        self.guid       = uuid.UUID(store_id).hex


