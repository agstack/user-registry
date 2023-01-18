from dbms import db


class BlackList(db.Model):
    __tablename__ = 'blacklist'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String())

    def __repr__(self):
        return '<blacklisted email{}>'.format(self.email)
