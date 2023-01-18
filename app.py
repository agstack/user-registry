import jwt as pyjwt
from app import app, db
import requests
from flask import Flask, make_response, request, render_template, flash, redirect, url_for, Markup, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import user as userModel, domainCheck
from utils import allowed_to_register, is_blacklisted
from forms import SignupForm, LoginForm, UpdateForm
from flask_jwt_extended import create_access_token, \
    get_jwt_identity, jwt_required, \
    JWTManager, current_user, \
    create_refresh_token, set_access_cookies, set_refresh_cookies, unset_access_cookies, unset_jwt_cookies

jwt = JWTManager(app, add_context_processor=True)


@app.route('/home', methods=['GET', 'POST'])
@jwt_required()
def home():
    return render_template('home.html')


@app.route('/asset-registry-home')
@jwt_required()
def asset_registry_home():
    """
    To send tokens to asset-registry
    """
    access_token = request.cookies.get('access_token_cookie')
    refresh_token = request.cookies.get('refresh_token_cookie')
    tokens = {'Authorization': 'Bearer ' + access_token}
    try:
        res = requests.post(app.config['ASSET_REGISTRY_BASE_URL'], headers=tokens, timeout=2)
        res.raise_for_status()
        if res.json() and res.json()['status'] == 200:
            flash(message="Tokens successfully delivered", category='info')
        else:
            flash(message="Something went wrong", category='danger')
    except requests.exceptions.ConnectionError:
        flash(message="Connection refused", category='danger')

    return make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home'))


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    """
    Missing auth header
    """
    flash(message='You need to login first!', category='warning')

    return make_response(login(), 401)


@jwt.expired_token_loader
def expired_token_callback(callback, callback2):
    ref_token = request.cookies.get('refresh_token_cookie')
    user = userModel.User.query. \
        filter_by(refresh_token=ref_token).first()
    try:
        pyjwt.decode(ref_token, app.config['SECRET_KEY'], algorithms="HS256")
    except pyjwt.ExpiredSignatureError:
        resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
        user.refresh_token = None
        user.access_token = None
        db.session.commit()
        unset_jwt_cookies(resp)
        return resp
    resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/refresh'))
    user.access_token = None
    db.session.commit()
    unset_access_cookies(resp)
    return resp


@app.route('/', methods=['GET', 'POST'])
@jwt_required(optional=True)
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()

        if not user:
            flash(message='You are not registered', category='danger')
        elif is_blacklisted(email):
            flash(message=f'"{email}" is blacklisted', category='danger')
        else:

            if check_password_hash(user.password, password):
                # generates the JWT Token
                additional_claims = {"domain": email.split('@')[1]}
                access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
                refresh_token = create_refresh_token(identity=user.id)
                resp = make_response(redirect(url_for('home')))
                user.access_token = access_token
                user.refresh_token = refresh_token
                db.session.commit()
                set_access_cookies(resp, access_token)
                set_refresh_cookies(resp, refresh_token)
                return resp
            else:
                flash(message='Incorrect Password!', category='danger')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
@jwt_required(optional=True)
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
                return make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
            else:

                flash(message=Markup(f'A user with email "{email}" already exists. Please  <a href="/" '
                                     f'class="alert-link">login</a>!'), category='info')

    return render_template('signup.html', form=form)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """
    This function is necessary since it places the logged-in user's data
    in the current_user
    Register a callback function that loads a user from your database whenever
    a protected route is accessed. This should return any python object on a
    successful lookup, or None if the lookup failed for any reason (for example
    if the user has been deleted from the database).
    """
    identity = jwt_data["sub"]
    return userModel.User.query.filter_by(id=identity).one_or_none()


@app.route("/refresh", methods=["GET"])
@jwt_required(refresh=True)
def refresh():
    """
    We are using the `refresh=True` options in jwt_required to only allow
    refresh tokens to access this route.
    """
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    resp = make_response(redirect(request.referrer))
    user = userModel.User.query.filter_by(id=current_user.id).first()
    user.access_token = access_token
    db.session.commit()
    set_access_cookies(resp, access_token)
    return resp


@app.route('/update', methods=['GET', 'POST'])
@jwt_required()
def update():
    form = UpdateForm()
    if form.validate_on_submit():

        # gets email and password
        email = form.email.data
        password = form.password.data
        phone_num = form.phone_num.data
        discoverable = form.discoverable.data
        user_to_update = userModel.User.query.filter_by(email=current_user.email).first()
        if email != current_user.email:
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
                    user_to_update.email = email
                    flash(message="Email address updated", category='info')
                    if current_user.domain_id != domain_id:
                        user_to_update.domain_id = domain_id
                        if domainCheck.DomainCheck.query.filter_by(
                                id=domain_id).first().belongs_to == domainCheck.DomainCheck.query.filter_by(
                            id=current_user.domain_id).first().belongs_to:
                            if domainCheck.DomainCheck.query.filter_by(
                                    id=domain_id).first().belongs_to == domainCheck.ListType.authorized:

                                flash(message="Added to authorized domain list", category='info')

                            elif domainCheck.DomainCheck.query.filter_by(
                                    id=domain_id).first().belongs_to == domainCheck.ListType.blue_list:
                                flash(message="Removed from authorized domain list", category='warning')

                else:

                    flash(message=f'A user with email "{email}" already exists.', category='info')
        if password != "" and not check_password_hash(user_to_update.password, password):
            user_to_update.password = generate_password_hash(password)
            flash(message="Password changed", category='info')
        if phone_num != current_user.phone_num:
            user_to_update.phone_num = phone_num
            flash(message="Phone number updated", category='info')
        if discoverable != current_user.discoverable:
            user_to_update.discoverable = discoverable
            flash(message="Discoverable field updated", category='info')

        db.session.commit()

    return render_template('update.html', form=form)


@app.route("/logout", methods=["GET"])
@jwt_required(refresh=True)
def logout():
    """
    Endpoint for revoking the current users access token. Saved the unique
    identifier (jti) for the JWT into our database.
    """
    user = userModel.User.query.filter_by(id=current_user.id).first()
    user.access_token = None
    user.refresh_token = None
    db.session.commit()
    resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
    unset_jwt_cookies(resp)
    return resp


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    """
    Callback function to check if a JWT exists in the database blocklist
    This function is necessary to check if the token supplied is logged out
    already
    """
    jti = jwt_payload["jti"]
    token = userModel.User.query \
        .filter_by(access_token=jti) \
        .one_or_none()

    return token is not None


@app.route("/domains", methods=['GET'])
def fetch_all_domains():
    """
    Fetching all the domains
    """
    domains = domainCheck.DomainCheck.query.all()
    domains = [domain.domain for domain in domains]
    return jsonify({
        "Message": "All domains",
        "Domains": domains
    }), 200


@app.route('/authority-token/', methods=['GET'])
def get_authority_token():
    try:
        args = request.args
        domain = args.get('domain')
        authority_token = db.session.query(domainCheck.DomainCheck.authority_token).filter(
            domainCheck.DomainCheck.domain == domain).first().authority_token
        if not authority_token:
            return make_response(jsonify({
                "Message": "Authority token not found"
            }), 404)
        return make_response(jsonify({
            "Message": f"Authority token fetched successfully for domain: {domain}",
            "Authority Token": authority_token
        }), 200)
    except AttributeError:
        return make_response(jsonify({
            "Message": "Authority token not found."
        }), 400)


if __name__ == '__main__':
    app.run()
