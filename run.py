import jwt
import datetime

from app import app, db
from flask import Flask, jsonify, make_response, request, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import user as userModel
from utils import check_email, allowed_to_register
from forms import SignupForm


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    # parses the incoming JSON request
    auth = request.get_json(force=True)

    if not auth or not auth['email'] or not auth['password']:
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = userModel.User.query \
        .filter_by(email=auth.get('email')) \
        .first()
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return make_response(jsonify({'token': token}), 200)

    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():

        # gets email and password
        email = form.email.data
        password = form.password.data
        phone_num = form.phone_num.data
        discoverable = form.discoverable.data
        token_or_allowed = allowed_to_register(email)
        if not token_or_allowed:
            flash(message='This email is blacklisted', category='danger')
        else:
            domain_id = token_or_allowed

        # checking for existing user
            user = userModel.User.query \
                .filter_by(email=email) \
                .first()
            if not user:
                # database ORM object
                user = userModel.User(
                    phone_num=phone_num,
                    email=email,
                    password=generate_password_hash(password),
                    domain_id=domain_id
                )
                # insert user
                db.session.add(user)
                db.session.commit()
                flash(message='You are registered successfully', category='success')
            else:

                flash(message=f'A user with email "{email}" already exists. Please login!', category='info')

    return render_template('signup.html', form=form)


@app.route('/user/<user_id>', methods=['PATCH'])
@userModel.User.token_required
def update(user_id):
    body = request.get_json(force=True)
    user = userModel.User.query.get(user_id)

    if not user:
        return make_response('User not found.', 400)

    for key, value in body.items():
        if key == 'email':
            value = value.strip()
            if not check_email(value):
                return make_response('Please provide a valid email address', 400)
            token_or_allowed = allowed_to_register(value)
            if not token_or_allowed:
                return make_response('Blacklisted email', 401)
            else:
                domain_id = token_or_allowed
                setattr(user, key, value)
                setattr(user, 'domain_id', domain_id)

        elif key == 'password':
            password = generate_password_hash(value)
            setattr(user, key, password)
        else:
            setattr(user, key, value)
    db.session.commit()

    return make_response('User updated successfully.', 200)
