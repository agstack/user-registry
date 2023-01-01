import random
import re
import string
from app.models import blackList, domainCheck
from app import db


# function for validating an Email
def check_email(email):
    # regex for validating an Email
    valid_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(valid_email, email):
        return True
    return False


def is_blacklisted(email):
    if blackList.BlackList.query.filter_by(email=email).first() is not None:
        return True
    return False



def allowed_to_register(email):
    if is_blacklisted(email):
        return False
    domain = email.split('@')[1]
    try:
        domain_belongs_to = domainCheck.DomainCheck.query \
            .filter_by(domain=domain) \
            .first().belongs_to
    except AttributeError:
        issue_auth_token(domain)
        return domainCheck.DomainCheck.query \
            .filter_by(domain=domain).first().id
    if domain_belongs_to == ListType.authorized:
        return domainCheck.DomainCheck.query \
            .filter_by(domain=domain).first().id
    if domain_belongs_to == ListType.blue_list:
        return False


def issue_auth_token(domain):
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    while domainCheck.DomainCheck.query.filter_by(authority_token=token).first() is not None:
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    add_domain = domainCheck.DomainCheck("0", domain, token)
    db.session.add(add_domain)
    db.session.commit()

