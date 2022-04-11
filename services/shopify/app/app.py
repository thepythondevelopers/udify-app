from re import I
from sys import api_version
from xml import dom
from flask import Flask,jsonify, current_app,request
import os 
import json
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pydantic import validate
from database import db,Accounts, Integrations,Stores
from flask_caching import Cache
from flask_cors import CORS, cross_origin
from pydantic_models import IntegrationModel
from constants.http_status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT
import validators
from itsdangerous import URLSafeTimedSerializer
import uuid
from constants.http_status_codes import HTTP_401_UNAUTHORIZED
import shopify
import binascii

DB_HOST = os.environ.get('DATABASE_HOST',"test-db.clbwo2sv0u1y.eu-west-1.rds.amazonaws.com")
DB_USER = os.environ.get('DATABASE_USER',"admin")
DB_PORT = os.environ.get('DATABASE_PORT',3306)
DATABASE = os.environ.get('DATABASE_NAME',"udify")
DB_PASSWORD = os.environ.get('DATABASE_PASSWORD',"admin1234")
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
cors = CORS(app)


@app.route("/add-integration", methods=["POST"])
@cross_origin()
@validate()
def add_integration(body: IntegrationModel):
      
    if(request.headers.get('X-Udify-Account-Id') == False):
    
        return jsonify({
            "error": "Authentication Token missing"
        }),HTTP_401_UNAUTHORIZED
    
    account_id = request.headers.get('X-Udify-Account-Id')
    store_api_key = body.store_api_key
    store_api_secret  = body.store_api_secret
    domain = body.domain

    account=Accounts.query.filter_by(guid=account_id).first()

    if account:
        # if(Stores.query.filter_by())
        # add condition for checking if already exists
        new_store = Stores(domain)
        new_integration = Integrations(store_api_key,store_api_secret,domain,account_id,new_store.guid)
        db.session.add(new_store)
        db.session.commit()
        db.session.add(new_integration)
        db.session.commit()
        shopify.Session.setup(api_key=store_api_key, secret=store_api_secret)
        shop_url = f"{domain}.myshopify.com"
        api_version = '2021-07'
        state = binascii.b2a_hex(os.urandom(15)).decode("utf-8")
        redirect_uri = "http://127.0.0.1:5000/oauth/authorize"
        scopes = ['read_products', 'read_orders']
        newSession = shopify.Session(shop_url, api_version)
        auth_url = newSession.create_permission_url(scopes, redirect_uri, state)
        return jsonify({
            "message": f"Store Added, please visit this link to complete the Setup: {auth_url}"
        }), HTTP_201_CREATED

    return jsonify({
        "error": "Invalid Account ID"
    }), HTTP_400_BAD_REQUEST


@app.route("/get-products/<string:integration_id>",methods=["GET"])
@cross_origin()
def get_products(integration_id:str):

    # if(request.headers.get('X-Udify-Account-Id') == False):

    #     return jsonify({
    #         "error": "Authentication Token missing"
    #     }),HTTP_401_UNAUTHORIZED

    # account_id = request.headers.get('X-Udify-Account-Id')
    # account=Accounts.query.filter_by(guid=account_id).first()
    # if account:
    integration = Integrations.query.filter_by(guid=integration_id).first()
    print(integration.guid)
    if integration:
        access_token = integration.store_api_secret
        shop_url = integration.domain + ".myshopify.com"
        print(shop_url)
        session = shopify.Session(shop_url, "2021-07", access_token)
        shopify.ShopifyResource.activate_session(session)
        products = shopify.Product.find()
        product_response = []
        for product in products:
            product_dict = {}
            product_dict['id'] = product.id
            product_dict['title'] = product.title
            # if(product.get):
            # product_dict['price'] = product.price
            product_dict['vendor'] = product.vendor
            product_response.append(product_dict)

        shopify.ShopifyResource.clear_session()

        return jsonify({
            "products":product_response
        }),HTTP_200_OK
    
    return jsonify({
        "error": "Invalid Integration Key"
    }), HTTP_400_BAD_REQUEST


@app.route("/get-orders/<string:integration_id>",methods=["GET"])
@cross_origin()
def get_orders(integration_id:str):

    # if(request.headers.get('X-Udify-Account-Id') == False):

    #     return jsonify({
    #         "error": "Authentication Token missing"
    #     }),HTTP_401_UNAUTHORIZED

    # account_id = request.headers.get('X-Udify-Account-Id')
    # account=Accounts.query.filter_by(guid=account_id).first()
    # if account:
    integration = Integrations.query.filter_by(guid=integration_id).first()
    print(integration.guid)
    if integration:
        access_token = integration.store_api_secret
        shop_url = integration.domain + ".myshopify.com"
        print(shop_url)
        session = shopify.Session(shop_url, "2021-07", access_token)
        shopify.ShopifyResource.activate_session(session)
        orders = shopify.Order.find()
        order_response = []
        for order in orders:
            order_dict = {}
            order_dict['id'] = order.app_id
            # order_dict['billing_address'] = order.billing_address
            # if(product.get):
            # product_dict['price'] = product.price
            order_dict['order_number'] = order.order_number
            order_dict['customer'] = (order.email)
            order_dict['total_price'] = order.current_total_price
            order_dict['financial_status'] = order.financial_status
            print(order.customer)

            order_response.append(order_dict)

        shopify.ShopifyResource.clear_session()

        return jsonify({
            "orders":order_response
        }),HTTP_200_OK
    
    return jsonify({
        "error": "Invalid Integration Key"
    }), HTTP_400_BAD_REQUEST



@app.route('/get-integrations', methods=["GET"])
def get_integrations():
    if(request.headers.get('X-Udify-Account-Id') == False):

        return jsonify({
            "error": "Authentication Token missing"
        }),HTTP_401_UNAUTHORIZED

    account_id = request.headers.get('X-Udify-Account-Id')
    account=Accounts.query.filter_by(guid=account_id).first()
    if account:
        integrations = Integrations.query.filter_by(account_id=account_id)
    
        if (integrations):
            integrations_response = []
            for integration in integrations:
                print(integration.guid) 
                integrations_dict = {}
                integrations_dict['domain'] =  integration.domain
                integrations_dict['id'] = integration.guid
                integrations_response.append(integrations_dict)
            return jsonify({
                "integrations": integrations_response
            }), HTTP_200_OK

        return jsonify({
            "message": "No Integrations for this Account"
        }), HTTP_400_BAD_REQUEST
    
    return jsonify({
        "error": "Invalid Account ID"
    }), HTTP_400_BAD_REQUEST



@app.route("/oauth/authorize",methods=["POST","GET"])
def callback():
    print(request)
    try:
        session = shopify.Session(request.args.get("shop"), '2021-07')
        access_token = session.request_token(request.args)
        print(access_token)
        integration = Integrations.query.filter_by(domain=request.args.get("shop").split('.')[0]).first()
        if integration: 
            integration.store_api_secret = access_token
            db.session.add(integration)
            db.session.commit()
    except Exception as error:
        print(error)
        return jsonify({
            "error": "Error in Authentication"
        }), HTTP_400_BAD_REQUEST
    
    return jsonify({
        "message": "Integration Complete!"
    }), HTTP_200_OK

    # store in DB

# @app.route("/shopify/callback")

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True,port=5000)




# For TEsting
# API KEY:     api_key="4a173617f7fcb14c997a55327a0287c3", 
# secret="0b60a5cc2f0b1574cb1883388c8dbed5"



# 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