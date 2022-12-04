from app import db


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
