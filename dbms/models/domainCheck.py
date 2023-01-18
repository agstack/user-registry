from dbms import db
import enum
from sqlalchemy_utils import ChoiceType


class ListType(enum.Enum):
    blue_list = "1"
    authorized = "0"


class DomainCheck(db.Model):
    __tablename__ = 'domaincheck'
    id = db.Column(db.Integer, primary_key=True)
    belongs_to = db.Column(ChoiceType(ListType, impl=db.String()))
    domain = db.Column(db.String())
    authority_token = db.Column(db.String(16), nullable=True)
    users = db.relationship('User', backref='domain', lazy=True)

    def __init__(self, belongs_to, domain, authority_token):
        self.belongs_to = belongs_to
        self.domain = domain
        self.authority_token = authority_token

    def __repr__(self):
        return '<domain {}>'.format(self.domain)
