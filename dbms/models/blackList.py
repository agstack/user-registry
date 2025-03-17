from dbms import db
import uuid
from sqlalchemy.dialects.postgresql import UUID

class BlockedUserEmails(db.Model):
    __tablename__ = 'blocked_user_email'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String())

    def __repr__(self):
        return '<blacklisted email{}>'.format(self.email)
