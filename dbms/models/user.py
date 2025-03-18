from dbms import db
from datetime import datetime
import uuid
from sqlalchemy.dialects.postgresql import UUID


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_num = db.Column(db.String())
    email = db.Column(db.String())
    password = db.Column(db.String())
    discoverable = db.Column(db.Boolean())
    access_token = db.Column(db.String(), nullable=True)
    refresh_token = db.Column(db.String(), nullable=True)
    domain_id = db.Column(UUID(), db.ForeignKey('domaincheck.id'),
                          nullable=True)
    activated = db.Column(db.Boolean, nullable=True)
    activated_on = db.Column(db.DateTime, nullable=True)
    country = db.Column(db.String(), nullable=True)
    lat_lng = db.Column(db.String(), nullable=True)
    api_key = db.Column(db.String(), nullable=True)
    client_secret = db.Column(db.String(), nullable=True)
    device_id = db.Column(db.String(), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(
        db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __init__(self, phone_num, email, password, country, lat_lng, device_id, activated=False, activated_on=None, domain_id=None):
        self.phone_num = phone_num
        self.email = email
        self.password = password
        self.discoverable = True  # default value True
        self.activated = activated
        self.activated_on = activated_on
        self.country = country
        self.lat_lng = lat_lng
        self.device_id = device_id
        self.domain_id = domain_id

    def __repr__(self):
        return '<id {}>'.format(self.id)
