from flask import Flask, jsonify, request, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask.helpers import url_for
from flask_pymongo import PyMongo
from flask_cors import CORS, cross_origin
from pymongo import MongoClient
import urllib.parse
import re
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import json
from bson import json_util
import numpy as np
import pandas as pd
import difflib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity



app = Flask(__name__)
cors = CORS(app)
jwt = JWTManager(app)
email = urllib.parse.quote_plus('shivani')
password = urllib.parse.quote_plus('Shivani@123')
app.config['MONGO_URI'] = 'mongodb+srv://%s:%s@cluster0.wsigl1o.mongodb.net/telstradb?retryWrites=true&w=majority' % (email, password)
app.config['CORS_Headers'] = 'Content-Type'
mongo = PyMongo(app)
db=mongo.db
users = mongo.db.users


#common pre-processing for recommendation
product_data_cursor= db.products.find()
product_data_list=list(product_data_cursor)

product_data = pd.DataFrame(product_data_list)
#print(product_data.head())
combined_features = product_data['category']+' '+product_data['brand']+' '+product_data['name']+' '+product_data['keyword']+' '+product_data['description']

vectorizer = TfidfVectorizer()
feature_vectors = vectorizer.fit_transform(combined_features)

similarity = cosine_similarity(feature_vectors)


# Signup Api

@app.route('/signup', methods=['POST'])
def signup():
    # Get user input
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    confirm_password = data['confirm_password']

    # Check if either of input fields are empty
    if not email or not password or not confirm_password or not username:
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
    
    # If username already exits
    if users.find_one({'username': username}):
        return jsonify({'message': 'This username is already taken.'}), 400

    # Hash password and save new user
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = {'email': email, 'username': username, 'password': hashed_password}
    users.insert_one(new_user)

    return jsonify({'message': 'User created successfully.'}), 201



# Login Api

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



# Add Product Api

@app.route('/addproduct', methods=['POST'])
def add_product():
    current_collection = mongo.db.products
    data = request.get_json()
    p_id = data['p_id']
    category = data['category']
    brand = data['brand']
    name = data['name']
    price = data['price']
    image = data['image']
    keyword = data['keyword']
    description = data['description']

    new_product = {'p_id': p_id, 'category': category, 'brand': brand, 'name': name, 'price': price, 'image': image, 'keyword':keyword, 'description':description}
    current_collection.insert_one(new_product)

    return jsonify({'message': 'Product added'})



# Get All Products Api

@app.route('/products', methods=['GET'])
def get_all_products():
    current_collection = mongo.db.products
    all_products = current_collection.find()
    docs_list  = list(all_products)
    products = []
    for doc in docs_list:
        product = {
            "_id": str(doc["_id"]),
            "p_id": doc["p_id"],
            "category": doc["category"],
            "brand": doc["brand"],
            "name": doc["name"],
            "price": doc["price"],
            "image": doc["image"],
            "keyword": doc["keyword"],
            "description": doc["description"]
        }

        products.append(product)

    return jsonify({"products":products}),200



# Searching Product with Query Api

@app.route('/search', methods=['GET'])
def search_by_query():
    query = request.args.get('q')
    print(query)
    current_collection = mongo.db.products
    # regex = re.compile(f".*{query}.*", re.IGNORECASE)
    all_products = current_collection.find({"$or":[{"p_id":{"$regex":query, "$options": "i"}},
                                                  {"category": {"$regex":query, "$options": "i"}},
                                                  {"brand":{"$regex":query, "$options": "i"}},
                                                  {"name":{"$regex":query, "$options": "i"}},
                                                  {"price":{"$regex":query, "$options": "i"}},
                                                  {"keyword":{"$regex":query, "$options": "i"}},
                                                  {"description":{"$regex":query, "$options": "i"}}] })
    docs_list = list(all_products)
    products = []
    for doc in docs_list:
        product = {
            "_id": str(doc["_id"]),
            "p_id": doc["p_id"],
            "category": doc["category"],
            "brand": doc["brand"],
            "name": doc["name"],
            "price": doc["price"],
            "image": doc["image"],
            "keyword": doc["keyword"],
            "description": doc["description"]
        }

        products.append(product)
    print(products)
    # products = list(current_collection.find({"category": re.compile(f".*{query}.*", re.IGNORECASE)}))


    return jsonify({"products":products}),200



# Single Product Api with Recommendation

@app.route('/product/<p_id>', methods = ['GET'])
def get_product(p_id):
    products=db.products
    product_info=[]
    p_id=int(p_id)
    recommendation_ids=get_recommendation(p_id)
    for p_id in recommendation_ids:
        data = products.find_one({"p_id" : str(p_id)})                                         
        product = {
            "p_id": data["p_id"],
            "category": data["category"],
            "brand": data["brand"],
            "name": data["name"],
            "price": data["price"],
            "image": data["image"],
            "description": data["description"]
        }
        product_info.append(product)
    return jsonify({"product_info": product_info})



# Adding Review to the Db API

@app.route('/review', methods= ['POST'])
def collect_review():
    current_collection = mongo.db.reviews
    data = request.get_json()
    p_id = data['p_id']
    review = data['review']
    rating = data['rating']
    review_analysis = ''

     # passing review for sentimental analysis
    sid_obj = SentimentIntensityAnalyzer()
    sentiment_dict = sid_obj.polarity_scores(review)
    if sentiment_dict['neg'] > sentiment_dict['pos'] and sentiment_dict['neg'] > sentiment_dict['neu']:
        review_analysis = 'Negative'

    elif sentiment_dict['pos'] > sentiment_dict['neg'] and sentiment_dict['pos'] > sentiment_dict['neu']: 
        review_analysis = 'Positive'

    else :
        review_analysis = 'Neutral'
        

    new_review = {'p_id': p_id, 'review': review, 'rating': rating, 'review_analysis': review_analysis}
    current_collection.insert_one(new_review)

    return jsonify({"message": "Review added Successfully"}), 200


# @app.route('/<name>', methods = ['GET'])
# @cross_origin()
# def retrieveFromName(name):
#     currentCollection = mongo.db.products
#     data = currentCollection.find_one({"name" : name})
#     return jsonify({'name' : data['name'], 'genre' : data['favGenre'], 'game' : data['favGame']})

#recommendation function for recommendation
def get_recommendation(product_id):
    recommendation_ids=[]
    similarity_score = list(enumerate(similarity[product_id]))

    sorted_similar_products= sorted(similarity_score, key = lambda x:x[1], reverse = True) 

    i = 0
    count=0
    prev_category_name=''
    for product in sorted_similar_products:
        id= product[0]
        category_name=product_data.loc[id]['category']
        if(id==product_id):
            recommendation_ids.append(id)
            continue
        elif(count<4 and prev_category_name!=category_name):
            recommendation_ids.append(id)
            count+=1
            if(count%2==0):
                prev_category_name=category_name
    print(recommendation_ids)
    print(type(recommendation_ids[0]))
    return recommendation_ids



if __name__ == '__main__':
    app.secret_key = 'secretivekey'
    app.run(debug = True)