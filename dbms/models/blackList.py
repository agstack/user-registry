from dbms import db


class BlockedUserEmails(db.Model):
    __tablename__ = 'blocked_user_email'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String())

    def __repr__(self):
        return '<blacklisted email{}>'.format(self.email)
