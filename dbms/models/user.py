from dbms import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    phone_num = db.Column(db.String())
    email = db.Column(db.String())
    password = db.Column(db.String())
    discoverable = db.Column(db.Boolean())
    access_token = db.Column(db.String(), nullable=True)
    refresh_token = db.Column(db.String(), nullable=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domaincheck.id'),
                          nullable=False)

    def __init__(self, phone_num, email, password, domain_id):
        self.phone_num = phone_num
        self.email = email
        self.password = password
        self.discoverable = True  # default value True
        self.domain_id = domain_id

    def __repr__(self):
        return '<id {}>'.format(self.id)