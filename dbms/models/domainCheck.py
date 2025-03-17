from dbms import db
import enum
from sqlalchemy_utils import ChoiceType
import uuid
from sqlalchemy.dialects.postgresql import UUID


class ListType(enum.Enum):
    blocked_authority_list = "1"
    authorized = "0"


class DomainCheck(db.Model):
    __tablename__ = 'domaincheck'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
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
