from flask import Flask, jsonify, request, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask.helpers import url_for
from flask_pymongo import PyMongo
from flask_cors import CORS, cross_origin
from pymongo import MongoClient
import urllib.parse
import re
import json
from bson import json_util



app = Flask(__name__)
cors = CORS(app)
jwt = JWTManager(app)
email = urllib.parse.quote_plus('shivani')
password = urllib.parse.quote_plus('Shivani@123')
app.config['MONGO_URI'] = 'mongodb+srv://%s:%s@cluster0.wsigl1o.mongodb.net/telstradb?retryWrites=true&w=majority' % (email, password)
app.config['CORS_Headers'] = 'Content-Type'
mongo = PyMongo(app)
users = mongo.db.users

@app.route('/signup', methods=['POST'])
def signup():
    # Get user input
    data = request.get_json()
    email = data['email']
    password = data['password']
    confirm_password = data['confirm_password']

    # Check if either of input fields are empty
    if not email or not password or not confirm_password:
        return jsonify({'message': 'Please enter all the details'}),400
    
    # Check if password matches the confirm password field
    if password != confirm_password:
        return jsonify({'message': 'Password dosen\'t match'}),401
    
    # Regex for email validation
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(regex, email):
        return jsonify({'error': 'Invalid email format'}), 400

    # Check if user already exists
    if users.find_one({'email': email}):
        return jsonify({'message': 'email already exists.'}), 400

    # Hash password and save new user
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = {'email': email, 'password': hashed_password}
    users.insert_one(new_user)

    return jsonify({'message': 'User created successfully.'}), 201


@app.route('/login', methods=['POST'])
def login():
    # Get user input
    data = request.get_json()
    email = data['email']
    password = data['password']

    # Find user in list of registered users
    user = users.find_one({'email': email})

    # Check if user exists and password is correct
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    # Generate access token and return it
    access_token = create_access_token(identity=user['email'])
    return jsonify({'access_token': access_token}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get email from JWT token
    email = get_jwt_identity()

    return jsonify({'message': f'Hello, {email}! This is a protected endpoint.'}), 200

@app.route('/products', methods=['GET'])
def get_all_products():
    current_collection = mongo.db.products
    all_products = current_collection.find()
    docs_list  = list(all_products)
    products = []
    for doc in docs_list:
        product = {
            "_id": str(doc["_id"]),
            "name": doc["name"],
            "image": doc["image"]
        }

        products.append(product)

    return jsonify({"products":products}),200
    


# @app.route('/<name>', methods = ['GET'])
# @cross_origin()
# def retrieveFromName(name):
#     currentCollection = mongo.db.products
#     data = currentCollection.find_one({"name" : name})
#     return jsonify({'name' : data['name'], 'genre' : data['favGenre'], 'game' : data['favGame']})



if __name__ == '__main__':
    app.secret_key = 'secretivekey'
    app.run(debug = True)