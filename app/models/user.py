from flask import jsonify, request
from functools import wraps
import jwt
from jwt.exceptions import DecodeError
import enum
from sqlalchemy_utils import ChoiceType
from app import db, app


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    phone_num = db.Column(db.String())
    email = db.Column(db.String())
    password = db.Column(db.String())
    discoverable = db.Column(db.Boolean())

    def __init__(self, phone_num, email, password):
        self.phone_num = phone_num
        self.email = email
        self.password = password
        self.discoverable = True  # default value True

    def __repr__(self):
        return '<id {}>'.format(self.id)

    def token_required(f):
        @wraps(f)
        def decorator(*args, **kwargs):

            token = request.headers['x-access-token'] if 'x-access-token' in request.headers else None
            if not token:
                return jsonify({'message': 'a valid token is missing'})
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            except DecodeError:
                return jsonify({'message': 'token is invalid'})

            return f(*args, **kwargs)

        return decorator


class ListType(enum.Enum):
    black_list = "0"
    blue_list = "1"


class DomainCheck(db.Model):
    __tablename__ = 'domaincheck'
    id = db.Column(db.Integer, primary_key=True)
    belongs_to = db.Column(ChoiceType(ListType, impl=db.String()))
    domain = db.Column(db.String())


    def __repr__(self):
        return '<domain {}>'.format(self.domain)