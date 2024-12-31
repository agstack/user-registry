import random
import re
import string
import secrets
from flask import request
import jwt
from dbms.models import domainCheck, blackList, user as userModel
from dbms import db, app
from sqlalchemy import func
from datetime import date, timedelta
from flask_jwt_extended import create_access_token


# function for validating an Email
def check_email(email):
    """
    This function takes in an email and checks if that email is valid or not
    """
    # regex for validating an Email
    valid_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(valid_email, email):
        return True
    return False


def is_blacklisted(email):
    """
    This function takes in an email and checks if it exists in the blocked list or not
    """
    if blackList.BlockedUserEmails.query.filter_by(email=email).first() is not None:
        return True
    return False


def allowed_to_register(email):
    """
    This function takes in an email and returns false if it is blacklisted. If the domain is already
    authorized, or it is blue-listed, it returns the domain_id. If the domain don't already exist in the database,
    it creates a new domain with no token and as blue listed
    """
    if is_blacklisted(email):
        return False
    domain = email.split('@')[1]
    try:
        domain_belongs_to = domainCheck.DomainCheck.query \
            .filter_by(domain=domain) \
            .first().belongs_to
    except AttributeError:
        add_domain = domainCheck.DomainCheck("1", domain, None)
        db.session.add(add_domain)
        db.session.commit()
        return domainCheck.DomainCheck.query \
            .filter_by(domain=domain).first().id
    if domain_belongs_to == domainCheck.ListType.authorized or domain_belongs_to == domainCheck.ListType.blocked_authority_list:
        return domainCheck.DomainCheck.query \
            .filter_by(domain=domain).first().id


def issue_auth_token(domain):
    """
    This function takes in a domain and issues a unique authority token for that domain
    """
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    while domainCheck.DomainCheck.query.filter_by(authority_token=token).first() is not None:
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    domain.authority_token = token
    domain.belongs_to = "0"
    db.session.add(domain)
    db.session.commit()


def get_row_count_by_month():
    """
    Fetch row count by month
    :return:
    """
    end_date = date.today()
    start_date = end_date - timedelta(days=365)
    rows = (
        db.session.query(
            func.date_trunc('month', userModel.User.created_at).label('month'),
            func.count().label('count')
        )
        .filter(userModel.User.created_at >= start_date)
        .group_by(func.date_trunc('month', userModel.User.created_at))
        .order_by(func.date_trunc('month', userModel.User.created_at))
        .all()
    )
    data_by_month = [{'month': row.month.strftime('%B'), 'count': row.count} for row in rows]
    return data_by_month


def get_row_count_by_country():
    """
    Fetch row count by country
    :return:
    """
    rows = (
        db.session.query(userModel.User.country.label('country'), db.func.count().label('count')).group_by(
            userModel.User.country).all()
    )
    count_by_country = [{'country': row.country, 'count': row.count} for row in rows]
    return count_by_country


def get_row_count_by_domain():
    """
    Fetch row count by domain with Authority Token
    :return:
    """
    try:
        count = db.session.query(domainCheck.DomainCheck).filter(
            domainCheck.DomainCheck.authority_token.isnot(None)).count()
        return count
    except Exception as e:
        raise e


def get_fields_count_by_domain(authority_tokens_list):
    """
    Fetch the fields count registered against the domains
    :return:
    """
    try:
        records = domainCheck.DomainCheck.query.filter(
            domainCheck.DomainCheck.authority_token.in_(authority_tokens_list)).all()
        authority_token_dict = {record.authority_token: record.domain for record in records}
        return authority_token_dict
    except Exception as e:
        raise e


def check_non_web_user_agent(user_agent):
    """
    Check if the request is either from Postman, Notebook, or a mobile device.
    """
    try:
        # Convert user_agent to lowercase for case-insensitive comparison
        user_agent = user_agent.lower()
        # Check for development user agents or mobile device user agents
        return (
                'postman' in user_agent or
                'python' in user_agent or
                'android' in user_agent or
                'iphone' in user_agent or
                'ipad' in user_agent or
                'mobile' in user_agent or
                'dart' in user_agent
        )
    except Exception as e:
        raise e


def get_bearer_token():
    token = None
    bearer = request.headers.get('Authorization')  # Bearer JWT token here
    if bearer and len(bearer.split()) > 1:
        token = bearer.split()[1]  # JWT token
    if not token and request.cookies.get('access_token_cookie'):  # check in cookies if not in headers
        token = request.cookies.get('access_token_cookie')
    return token


def get_domain_from_jwt():
    """
    Get domain of the logged in user
    :return:
    """
    token = get_bearer_token()
    domain = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")['domain']
    return domain


def generate_secret_key(client_secret=False):
    """
    Generates a secret key
    Generates client secret as a JWT with logged-in user domain
    Needs domain later on when registering a field in Asset Registry
    """
    try:
        if client_secret:
            domain = get_domain_from_jwt()
            client_secret_key = create_access_token(identity=domain, expires_delta=False)
            return client_secret_key
        # Generate a 32-byte random secret key
        secret_key = secrets.token_hex(32)
        return secret_key
    except Exception as e:
        raise e
