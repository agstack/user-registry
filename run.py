from datetime import timedelta, datetime, timezone

from app import app, db
from flask import Flask, jsonify, make_response, request, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import user as userModel
from app.models import tokenBlocklist
from app.models.tokenBlocklist import TokenBlocklist
from utils import check_email, allowed_to_register
from forms import SignupForm
from flask_jwt_extended import create_access_token, \
    get_jwt_identity, jwt_required, \
    JWTManager, current_user, \
    create_refresh_token, get_jwt

# If true this will only allow the cookies that contain your JWTs to be sent
# over https. In production, this should always be set to True
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
# following must be made true in production
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
jwt = JWTManager(app)


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
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return make_response(jsonify(access_token=access_token, refresh_token=refresh_token), 200)

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


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return userModel.User.query.filter_by(id=identity).one_or_none()


# We are using the `refresh=True` options in jwt_required to only allow
# refresh tokens to access this route.
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@app.route('/user', methods=['PATCH'])
@jwt_required()
def update():
    body = request.get_json(force=True)
    user = current_user

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


# Endpoint for revoking the current users access token. Saved the unique
# identifier (jti) for the JWT into our database.
@app.route("/logout", methods=["DELETE"])
@jwt_required(verify_type=False)
def modify_token():
    token = get_jwt()
    jti = token["jti"]
    ttype = token["type"]
    now = datetime.now(timezone.utc)
    db.session.add(tokenBlocklist.TokenBlocklist(jti=jti, type=ttype, created_at=now))
    db.session.commit()
    return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None
