from flask import jsonify, request
from functools import wraps
import jwt
from app import db, app


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    phone_num = db.Column(db.String())
    email = db.Column(db.String())
    password = db.Column(db.String())

    def __init__(self, phone_num, email, password):
        self.phone_num = phone_num
        self.email = email
        self.password = password

    def __repr__(self):
        return '<id {}>'.format(self.id)

    def token_required(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = None
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

            if not token:
                return jsonify({'message': 'a valid token is missing'})
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = User.query.filter_by(id=data['id']).first()
            except:
                return jsonify({'message': 'token is invalid'})

            return f(current_user, *args, **kwargs)

        return decorator
