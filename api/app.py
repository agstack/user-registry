from flask import Flask, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime

app = Flask(__name__)
app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
from models import User

migrate = Migrate(app, db)


@app.route('/')
def hello_world():
    return 'Hello World!'


# User Database Route
# this route sends back list of users
@app.route('/user', methods=['GET'])
@User.token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'id': user.id,
            'email': user.email,
            'phone_num': user.phone_num,
            'discoverable': user.discoverable
        })

    return jsonify({'users': output})


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # parses the incoming JSON request
    auth = request.get_json(force=True)

    if not auth or not auth['email'] or not auth['password']:
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return make_response(jsonify({'token': token}), 200)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # parses the incoming JSON request
    data = request.get_json(force=True)

    # gets email and password
    email = data['email']
    password = data['password']
    phone_num = data['phone_num']

    # checking for existing user
    user = User.query \
        .filter_by(email=email) \
        .first()
    if not user:
        # database ORM object
        user = User(
            phone_num=phone_num,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 200)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


# route to uodate the user
@app.route('/user/<user_id>', methods=['POST'])
def update(user_id):
    body = request.get_json(force=True)
    user = User.query.get(user_id)
    if not user:
        return make_response('User not found.', 400)
    for key, value in body.items():
        setattr(user, key, value)
    db.session.commit()

    return make_response('User updated successfully.', 200)


if __name__ == '__main__':
    app.run()
