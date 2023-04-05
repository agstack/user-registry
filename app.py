import json
import calendar

import jwt as pyjwt
from shapely.geometry import Point
import geopandas as gpd
import plotly
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest

import utils
from dbms import app, db, csrf
import requests
from flask_migrate import Migrate
import datetime

from flask import Flask, make_response, request, render_template, flash, redirect, Markup, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dbms.models import user as userModel
from utils import allowed_to_register, is_blacklisted
from forms import SignupForm, LoginForm, UpdateForm
from flask_jwt_extended import create_access_token, \
    get_jwt_identity, jwt_required, \
    JWTManager, current_user, \
    create_refresh_token, set_access_cookies, unset_access_cookies, unset_jwt_cookies

from utils_activation.email import send_email
from utils_activation.token import generate_confirmation_token, confirm_token
from utils import issue_auth_token
from dbms.models import user, blackList, domainCheck

migrate = Migrate(app, db)

jwt = JWTManager(app, add_context_processor=True)


def get_identity_if_logedin():
    try:
        return get_jwt_identity()
    except Exception:
        pass


@app.route('/home', methods=['GET', 'POST'])
@jwt_required()
def home():
    return render_template('home.html', is_user_activated=app.is_user_activated)


@app.route('/asset-registry-home')
@jwt_required()
def asset_registry_home():
    """
    To send tokens to asset-registry
    """
    if request.is_json:
        # this will run if json request
        json_req = True
    else:
        # this will run if website form request
        json_req = False
    access_token = request.cookies.get('access_token_cookie')
    tokens = {'Authorization': 'Bearer ' + access_token}
    try:
        res = requests.get(app.config['ASSET_REGISTRY_BASE_URL'], headers=tokens, timeout=2)
        res.raise_for_status()
        if res.json() and res.json()['status'] == 200:
            msg = "Tokens successfully delivered"
            flash(message=msg, category='info')
        else:
            msg = "Something went wrong"
            flash(message=msg, category='danger')
    except Exception as e:
        msg = "Connection refused"
        flash(message=msg, category='danger')
    if json_req:
        return jsonify({'message': msg, 'token': tokens}), 200
    return redirect(app.config['ASSET_REGISTRY_BASE_URL_FE'], 200)


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    """
    Missing auth header
    """
    flash(message='You need to login first!', category='warning')

    return redirect(url_for("login", next=request.url))


@jwt.expired_token_loader
def expired_token_callback(callback, callback2):
    ref_token = request.cookies.get('refresh_token_cookie')
    user = userModel.User.query. \
        filter_by(refresh_token=ref_token).first()
    try:
        pyjwt.decode(ref_token, app.config['SECRET_KEY'], algorithms="HS256")
    except pyjwt.ExpiredSignatureError:
        resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
        if user:
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
@csrf.exempt
def login():
    user = get_identity_if_logedin()
    asset_registry = False
    if request.method == 'POST':
        try:
            data = request.json
            asset_registry = data.get('asset_registry', False)
        except BadRequest:
            asset_registry = False
    if user:
        if not asset_registry:
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home')
        else:
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/asset-registry-home')
    try:
        # this will run if json request
        data = MultiDict(mapping=request.json)
        json_req = True
        app.config["WTF_CSRF_ENABLED"] = False
        form = LoginForm(data)
    except BadRequest:
        # this will run if website form request
        json_req = False
        form = LoginForm()
    # next url for redirecting after login
    next_url = form.next.data
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()

        if not user:
            msg = 'You are not registered'
            flash(message=msg, category='danger')
        elif is_blacklisted(email):
            msg = f'"{email}" is blacklisted'
            flash(message=msg, category='danger')
        else:
            # set global flag for user activation accordingly
            if not user.activated:
                app.is_user_activated = False
            else:
                app.is_user_activated = True
            if check_password_hash(user.password, password):
                # generates the JWT Token
                additional_claims = {"domain": email.split('@')[1], "is_activated": user.activated}
                access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
                refresh_token = create_refresh_token(identity=user.id)
                if not asset_registry and next_url != 'None':
                    resp = make_response(redirect(next_url))
                elif not asset_registry:
                    resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home'))
                else:
                    resp = make_response(jsonify({'access_token': access_token, 'refresh_token': refresh_token}))
                user.access_token = access_token
                user.refresh_token = refresh_token
                db.session.commit()
                if not asset_registry and json_req:
                    resp = make_response(jsonify({"access_token": access_token, "refresh_token": refresh_token}))
                    resp.set_cookie('access_token_cookie', access_token)
                    resp.set_cookie('refresh_token_cookie', refresh_token)

                    return resp
                resp.set_cookie('access_token_cookie', access_token, httponly=True,
                                max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'])
                resp.set_cookie('refresh_token_cookie', refresh_token, httponly=True,
                                max_age=app.config['JWT_REFRESH_TOKEN_EXPIRES'])
                return resp
            else:
                msg = 'Incorrect Password!'
                flash(message=msg, category='danger')
        if json_req:
            return make_response(jsonify({"message": msg}), 401)
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
@jwt_required(optional=True)
def signup():
    try:
        # this will run if json request
        data = MultiDict(mapping=request.json)
        json_req = True
        app.config["WTF_CSRF_ENABLED"] = False
        form = SignupForm(data)
    except BadRequest:
        # this will run if website form request
        json_req = False
        form = SignupForm()
    if form.validate_on_submit():
        # gets email and password
        email = form.email.data
        password = form.password.data
        phone_num = form.phone_num.data
        discoverable = form.discoverable.data
        token_or_allowed = allowed_to_register(email)
        if not token_or_allowed:
            msg = 'This email is blacklisted'
            flash(message=msg, category='danger')
        else:
            domain_id = token_or_allowed

            # checking for existing user
            user = userModel.User.query \
                .filter_by(email=email) \
                .first()
            if not user:
                country = ''
                p = None
                if discoverable:
                    # get user lat lng
                    lat = form.lat.data
                    lng = form.lng.data
                    if not lat or not lng:
                        msg = 'Allow Access to Location to be Discoverable.'
                        flash(message=msg, category='danger')
                        return render_template('signup.html', form=form)
                    # read shp file for country
                    worldShpFile = app.static_folder + '/99bfd9e7-bb42-4728-87b5-07f8c8ac631c2020328-1-1vef4ev.lu5nk.shp'
                    wrs_gdf = gpd.read_file(worldShpFile)
                    wrs_gdf = wrs_gdf.to_crs(4326)
                    p = Point([lng, lat])
                    try:
                        country = wrs_gdf[wrs_gdf.contains(p)].reset_index(drop=True).CNTRY_NAME.iloc[0]
                    except Exception as e:
                        country = ''
                # database ORM object
                user = userModel.User(
                    phone_num=phone_num,
                    email=email,
                    password=generate_password_hash(password),
                    domain_id=domain_id,
                    activated_on=None,
                    country=country,
                    lat_lng="{}, {}".format(p.y, p.x) if p else None
                )
                # insert user
                db.session.add(user)
                db.session.commit()
                token = generate_confirmation_token(user.email)
                confirm_url = url_for('activate_email', token=token, _external=True)
                html = render_template('activation-email.html', confirm_url=confirm_url)
                subject = "Please confirm your email"
                send_email(user.email, subject, html)
                flash('A confirmation email has been sent via email.', 'success')
                return make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
                msg = 'Signed up'
                if json_req:
                    return jsonify({"message": msg})
                return make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
            else:
                msg = 'A user with this email already exists'
                flash(message=Markup(f'A user with email "{email}" already exists. Please  <a href="/" '
                                     f'class="alert-link">login</a>!'), category='info')
        if json_req:
            return jsonify({"message": msg})
    return render_template('signup.html', form=form)


@app.route('/activate/<token>')
@jwt_required()
def activate_email(token):
    """
    Activate the user account
    """
    try:
        email = confirm_token(token)
        if email == current_user.email:
            user = userModel.User.query.filter_by(email=email).first_or_404()
            if user.activated:
                flash(message='Account already activated.', category='success')
            else:
                user.activated = True
                user.activated_on = datetime.datetime.now()
                db.session.add(user)
                db.session.commit()
                app.is_user_activated = True
                flash('You have activated your account. Thanks!', 'success')
                return make_response(redirect(url_for('logout')))
        else:
            flash(message="Invalid activation link!", category='danger')
    except:
        flash(message='The confirmation link is invalid or has expired.', category='danger')
    return make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home'))


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
    try:
        data = MultiDict(mapping=request.json)
        json_req = True
        app.config["WTF_CSRF_ENABLED"] = False
        form = UpdateForm(data)
        if form.email.data is None:
            form.email.data = current_user.email
        if form.phone_num.data is None:
            form.phone_num.data = current_user.phone_num
        if form.discoverable.data is None:
            form.discoverable.data = current_user.discoverable
        if form.password.data is None:
            form.password.data = ""
            form.confirm_pass.data = ""

    except BadRequest:
        json_req = False
        form = UpdateForm()
    if form.validate_on_submit():

        # gets email and password
        email = form.email.data
        password = form.password.data
        phone_num = form.phone_num.data
        discoverable = form.discoverable.data
        json_msg = ""
        user_to_update = userModel.User.query.filter_by(email=current_user.email).first()
        if email != "" and email != current_user.email:
            token_or_allowed = allowed_to_register(email)
            if not token_or_allowed:
                msg = 'This email is blacklisted'
                json_msg = json_msg + ". " + msg
                flash(message=msg, category='danger')
            else:
                domain_id = token_or_allowed

                # checking for existing user
                user = userModel.User.query \
                    .filter_by(email=email) \
                    .first()
                if not user:
                    user_to_update.email = email
                    msg = "Email address updated"
                    json_msg = json_msg + ". " + msg
                    flash(message=msg, category='info')
                    if current_user.domain_id != domain_id:
                        user_to_update.domain_id = domain_id
                        if domainCheck.DomainCheck.query.filter_by(
                                id=domain_id).first().belongs_to == domainCheck.DomainCheck.query.filter_by(
                            id=current_user.domain_id).first().belongs_to:
                            if domainCheck.DomainCheck.query.filter_by(
                                    id=domain_id).first().belongs_to == domainCheck.ListType.authorized:
                                msg = "Added to authorized domain list"
                                json_msg = json_msg + ". " + msg
                                flash(message=msg, category='info')

                            elif domainCheck.DomainCheck.query.filter_by(
                                    id=domain_id).first().belongs_to == domainCheck.ListType.blocked_authority_list:
                                msg = "Removed from authorized domain list"
                                json_msg = json_msg + ". " + msg
                                flash(message=msg, category='warning')

                else:
                    msg = f'A user with email "{email}" already exists.'
                    json_msg = json_msg + ". " + msg
                    flash(message=msg, category='info')
        if password != "" and not check_password_hash(user_to_update.password, password):
            user_to_update.password = generate_password_hash(password)
            msg = "Password changed"
            json_msg = json_msg + ". " + msg
            flash(message=msg, category='info')
        if phone_num != "" and phone_num != current_user.phone_num:
            user_to_update.phone_num = phone_num
            msg = "Phone number updated"
            json_msg = json_msg + ". " + msg
            flash(message=msg, category='info')
        if discoverable != current_user.discoverable:
            user_to_update.discoverable = discoverable
            msg = "Discoverable field updated"
            json_msg = json_msg + ". " + msg
            flash(message=msg, category='info')

        db.session.commit()
        if json_req:
            if json_msg != "" and json_msg[0] == ".":
                json_msg = json_msg[2:]
                return jsonify({"message": json_msg}), 202
            return jsonify({'message': "Nothing to be updated"}), 200

    return render_template('update.html', form=form)


@app.route("/logout", methods=["GET"])
@jwt_required(refresh=True)
def logout():
    """
    Endpoint for revoking the current users access token. Saved the unique
    identifier (jti) for the JWT into our database.
    """
    print('here in ur logout')
    user = userModel.User.query.filter_by(id=current_user.id).first()
    user.access_token = None
    user.refresh_token = None
    db.session.commit()
    try:
        print(request)
        asset_registry = request.json.get('asset_registry', False)
        print('in asset', asset_registry)
    except BadRequest:
        resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
        requests.get(app.config['ASSET_REGISTRY_BASE_URL'] + '/logout',
                     timeout=2)  # logout from Asset Registry as well
        unset_jwt_cookies(resp)
        print('failed')
        return resp
    resp = make_response(jsonify({"message": "Logged out"}), 200)
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


@app.route("/domains", methods=['POST'])
def authorize_a_domain():
    """
    Authorize a domain, will have an authority token
    """
    try:
        data = json.loads(request.data.decode('utf-8'))
        domain = data.get('domain')
        if not domain:
            return make_response(jsonify({
                "message": "Domain is required."
            }), 400)
        domain = domainCheck.DomainCheck.query.filter_by(
            domain=domain).first()
        if not domain:
            return make_response(jsonify({
                "message": "Domain not found."
            }), 400)
        if domain.authority_token:
            return make_response(jsonify({
                "message": "Domain already authorized."
            }), 200)
        issue_auth_token(domain)
        return jsonify({
            "Message": "Domain Authorized",
            "Domain": domain.domain
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Authorizing Domain Error',
            'error': f'{e}'
        }), 401


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


@app.route('/resend')
@jwt_required(refresh=True)
def resend_confirmation():
    """
    Resend the account activation email
    """
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('activate_email', token=token, _external=True)
    html = render_template('activation-email.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    try:
        # total user count
        user_count = userModel.User.query \
            .count()
        domain_count = utils.get_row_count_by_domain()
        row_count_by_month = utils.get_row_count_by_month()
        # count by month
        current_month = datetime.datetime.now().month
        last_12_months = [calendar.month_name[1:][i] for i in
                          range(current_month - 12, current_month)]
        last_12_months_count = [next((e['count'] for e in row_count_by_month if e['month'] == month), 0) for month in
                                last_12_months]
        # count by country
        row_count_by_country = utils.get_row_count_by_country()
        count = []
        country = []
        for element in row_count_by_country:
            count.append(element['count'])
            country.append(element['country'] if element['country'] else 'Other')
        # graph plot
        graphs = [
            dict(
                data=[
                    dict(
                        x=last_12_months,
                        y=last_12_months_count,
                        type='bar'
                    ),
                ],
                layout=dict(
                    title='Registered Users of last 12 month',
                    yaxis=dict(fixedrange=True),
                    xaxis=dict(fixedrange=True)
                ),
                config=dict(displayModeBar=False)
            ),
            dict(
                data=[
                    dict(
                        values=count,
                        labels=country,
                        type='pie'
                    ),
                ],
                layout=dict(
                    title='Registered Users Country',
                    yaxis=dict(fixedrange=True),
                    xaxis=dict(fixedrange=True)
                ), config=dict(displayModeBar=False)
            )
        ]

        # Add "ids" to each of the graphs
        ids = ['graph-{}'.format(i) for i, _ in enumerate(graphs)]
        graphJSON = json.dumps(graphs, cls=plotly.utils.PlotlyJSONEncoder)

        return render_template('dashboard.html',
                               ids=ids,
                               graphJSON=graphJSON, user_count=user_count, domain_count=domain_count)
    except Exception as e:
        return jsonify({
            'message': 'Dashboard Error',
            'error': f'{e}'
        }), 401


@app.route("/fields-count-by-domain", methods=['GET'])
def fields_count_by_domain():
    """
    Fetch the respective domains given the authority tokens
    """
    try:
        data = eval(request.headers['Authority-Tokens'])
        authority_token_dict = utils.get_fields_count_by_domain(data)
        return jsonify({
            "Message": "Authority Tokens Dictionary",
            "authority_token_dict": authority_token_dict
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Fetching Domains with authority tokens Error',
            'error': f'{e}'
        }), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0')
