import json
import calendar

import jwt as pyjwt
from shapely.geometry import Point
import geopandas as gpd
import plotly
from werkzeug.exceptions import BadRequest

import utils
from dbms import app, db, csrf
import requests
from flask_migrate import Migrate
import datetime

from flask import Flask, make_response, request, render_template, flash, redirect, Markup, jsonify, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from dbms.models import user as userModel
from utils import allowed_to_register, is_blacklisted, check_email
from forms import SignupForm, LoginForm, UpdateForm, ForgotForm, PasswordResetForm
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
@csrf.exempt
def home():
    return render_template('home.html', is_user_activated=app.is_user_activated)


@app.route('/asset-registry-home')
@jwt_required()
@csrf.exempt
def asset_registry_home():
    """
    To send tokens to asset-registry
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    access_token = request.cookies.get('access_token_cookie')
    refresh_token = request.cookies.get('refresh_token_cookie')
    tokens = {'Authorization': 'Bearer ' + access_token, 'refresh_token': refresh_token}
    # try:
    #     # res = requests.get(app.config['ASSET_REGISTRY_BASE_URL'], headers=tokens, timeout=2)
    #     res.raise_for_status()
    #     if res.json() and res.status_code == 200:
    #         msg = "Tokens successfully delivered"
    #         flash(message=msg, category='info')
    #     else:
    #         msg = "Something went wrong"
    #         flash(message=msg, category='danger')
    # except Exception as e:
    #     msg = "Connection refused"
    #     flash(message=msg, category='danger')
    if postman_notebook_request:
        return jsonify({'message': "", 'token': tokens})
    return redirect(app.config['ASSET_REGISTRY_BASE_URL_FE'], code=200)


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    """
    Missing auth header
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    if postman_notebook_request:
        return jsonify({'message': 'Need to Login.'}), 401
    flash(message='Need to Login.', category='warning')

    return redirect(url_for("login", next=request.url))


@jwt.expired_token_loader
def expired_token_callback(callback, callback2):
    ref_token = request.cookies.get('refresh_token_cookie')
    user = userModel.User.query. \
        filter_by(refresh_token=ref_token).first()
    try:
        pyjwt.decode(ref_token, app.config['SECRET_KEY'], algorithms="HS256")
    except:
        resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
        if user:
            user.refresh_token = None
            user.access_token = None
        db.session.commit()
        unset_jwt_cookies(resp)
        return resp
    resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/refresh'))
    db.session.commit()
    unset_access_cookies(resp)
    return resp


@app.route('/', methods=['GET', 'POST'])
@jwt_required(optional=True)
@csrf.exempt
def login():
    app.config["WTF_CSRF_ENABLED"] = False
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)

   # More comprehensive mobile device detection
    mobile_keywords = [
        'mobile', 'android', 'iphone', 'ipad', 'ipod',
        'blackberry', 'windows phone', 'opera mini',
        'samsung', 'huawei', 'xiaomi', 'oppo', 'vivo'
    ]
    is_mobile = any(keyword in user_agent.lower()
                    for keyword in mobile_keywords)
    device_id = request.headers.get('X-DEVICE-ID') if is_mobile else None

    # First, check if user is already logged in using JWT
    user = get_identity_if_logedin()

    # If no logged-in user but `device_id` is present, try logging in via device_id
    if not user and device_id:
        user = userModel.User.query.filter_by(device_id=device_id).first()
        if user:
            # Generate JWT Tokens
            additional_claims = {"domain": "mobile_login", "is_activated": user.activated, "uuid": f"{user.id}"}
            access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
            refresh_token = create_refresh_token(identity=user.id)

            # Store tokens in user model
            user.access_token = access_token
            user.refresh_token = refresh_token
            db.session.commit()

            # Return response similar to Postman requests
            resp = make_response(jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200)
            resp.set_cookie('access_token_cookie', access_token)
            resp.set_cookie('refresh_token_cookie', refresh_token)
            return resp
        else:
            return jsonify({"message": "Invalid Device ID"}), 400

    if user:
        if not postman_notebook_request:
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home'), 302
        elif postman_notebook_request or (is_mobile and device_id):
            userData = userModel.User.query \
                .filter_by(id=user) \
                .first()
            resp = make_response(jsonify({"access_token": userData.access_token, "refresh_token": userData.refresh_token}), 200)
            resp.set_cookie('access_token_cookie', userData.access_token)
            resp.set_cookie('refresh_token_cookie', userData.refresh_token)
            return resp

    asset_registry = False
    # this will run if website form request
    form = LoginForm()
    # next url for redirecting after login
    next_url = form.next.data
    if request.headers.get('X-ASSET-REGISTRY') == 'True':
        asset_registry = True
        email = request.headers.get('X-EMAIL')
        password = request.headers.get('X-PASSWORD')
    elif form.validate_on_submit():
        email = form.email.data
        password = form.password.data

    if not asset_registry and form.validate_on_submit() or asset_registry:
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if not user:
            msg = 'Invalid email or password.'
            if postman_notebook_request:
                return jsonify({'message': msg}), 401
            else:
                flash(message=msg, category='danger')
                return redirect(app.config['DEVELOPMENT_BASE_URL']), 302
        elif is_blacklisted(email):
            msg = f'"{email}" is blacklisted'
            flash(message=msg, category='danger')
            if postman_notebook_request:
                return jsonify({'message': msg}), 403

        # set global flag for user activation accordingly
        if user and not user.activated:
            app.is_user_activated = False
        else:
            app.is_user_activated = True

        if check_password_hash(user.password, password):
            # generates the JWT Token
            additional_claims = {"domain": email.split('@')[1], "is_activated": user.activated, "uuid": f"{user.id}"}
            access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
            refresh_token = create_refresh_token(identity=user.id)
            tokens = {'Authorization': 'Bearer ' + access_token, 'X-Refresh-Token': refresh_token}
            if not asset_registry:
                try:
                    requests.get(app.config['ASSET_REGISTRY_BASE_URL'], headers=tokens)
                except Exception as e:
                    return jsonify({
                        'message': 'Fetch Session Cookies Error!',
                        'error': f'{e}'
                    }), 400
            if not asset_registry and next_url != 'None':
                resp = make_response(redirect(next_url), 302)
            elif not asset_registry:
                resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home'), 302)
            else:
                resp = make_response(jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200)
            user.access_token = access_token
            user.refresh_token = refresh_token
            db.session.commit()
            if not asset_registry and postman_notebook_request:
                resp = make_response(jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200)
                resp.set_cookie('access_token_cookie', access_token)
                resp.set_cookie('refresh_token_cookie', refresh_token)
                return resp
            resp.set_cookie('access_token_cookie', access_token)
            resp.set_cookie('refresh_token_cookie', refresh_token)
            return resp
        else:
            msg = 'Incorrect Password!'
            flash(message=msg, category='danger')
            if postman_notebook_request:
                return jsonify({'message': msg}), 401
    if postman_notebook_request:
        return jsonify({"message": "Invalid request or missing credentials"}), 400
    return render_template('login.html', form=form), 200


@app.route('/signup', methods=['GET', 'POST'])
@jwt_required(optional=True)
@csrf.exempt
def signup():
    try:
        app.config["WTF_CSRF_ENABLED"] = False
        user_agent = request.headers.get('User-Agent')
        postman_notebook_request = utils.check_non_web_user_agent(user_agent)
        device_id = request.headers.get('X-DEVICE-ID')  # Identify mobile request

        # If device_id is present, skip form validation
        if device_id:
            # Check if user already exists with the same device_id
            existing_user = userModel.User.query.filter_by(device_id=device_id).first()
            if existing_user:
                return jsonify({"message": "User already exists with this device ID"}), 400

            # Automatically activate user
            activated_on = datetime.datetime.now()

            # Create user without requiring email, password, or phone number
            new_user = userModel.User(
                phone_num=None,
                email=None,
                password=None,
                country=None,
                lat_lng=None,
                device_id=device_id,
                activated=True,
                activated_on=activated_on,
            )

            db.session.add(new_user)
            db.session.commit()

            # Return the user's UUID along with the success message
            return jsonify({
                "message": "User created successfully", 
                "device_id": device_id,
                "user_id": str(new_user.id)
            }), 201


        form = SignupForm()
        if form.validate_on_submit():
            # gets email and password
            email = form.email.data
            password = form.password.data
            phone_num = form.phone_num.data
            discoverable = form.discoverable.data
            
            # Set discoverable to False if lat/lng not provided
            if discoverable and (not form.lat.data or not form.lng.data):
                discoverable = False
                
            token_or_allowed = allowed_to_register(email)
            if not token_or_allowed:
                msg = 'This email is blacklisted'
                if postman_notebook_request:
                    return jsonify({"message": msg})
                else:
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
                            if postman_notebook_request:
                                return jsonify({"message": msg}), 400
                            else:
                                return render_template('signup.html', form=form), 400
                        # read shp file for country
                        worldShpFile = app.static_folder + '/99bfd9e7-bb42-4728-87b5-07f8c8ac631c2020328-1-1vef4ev.lu5nk.shp'
                        wrs_gdf = gpd.read_file(worldShpFile)
                        wrs_gdf = wrs_gdf.to_crs(4326)
                        p = Point([lng, lat])
                        try:
                            country = wrs_gdf[wrs_gdf.contains(p)].reset_index(drop=True).CNTRY_NAME.iloc[0]
                        except Exception as e:
                            country = ''
                    # Convert UUID to string if it's a UUID object
                    if domain_id and hasattr(domain_id, 'hex'):
                        domain_id = str(domain_id)
                    # database ORM object
                    user = userModel.User(
                        phone_num=phone_num,
                        email=email,
                        password=generate_password_hash(password),
                        country=country,
                        lat_lng="{}, {}".format(p.y, p.x) if p else None,
                        device_id=device_id,
                        activated=False,
                        activated_on=None,
                        domain_id=domain_id,
                    )
                    # insert user
                    db.session.add(user)
                    db.session.commit()
                    token = generate_confirmation_token(user.email)
                    confirm_url = url_for('activate_email', token=token, _external=True)
                    html = render_template('activation-email.html', confirm_url=confirm_url)
                    subject = "Please confirm your email"
                    send_email(user.email, subject, html)
                    msg = 'A confirmation email has been sent via email.'
                    if postman_notebook_request:
                        return jsonify({
                            "message": msg,
                            "user_id": str(user.id)
                        }), 201  # Created
                    else:
                        flash(msg, 'success')
                        return make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
                else:
                    msg = 'A user with this email already exists'
                    if postman_notebook_request:
                        return jsonify({"message": msg}), 409  # Conflict
                    else:
                        flash(message=Markup(f'A user with email "{email}" already exists. Please  <a href="/" '
                                            f'class="alert-link">login</a>!'), category='info')
        return render_template('signup.html', form=form), 200  # OK
    except Exception as e:
                # Log the error for debugging
        print(f"Signup Error: {str(e)}")
        
        # Return appropriate response based on request type
        if postman_notebook_request:
            return jsonify({
                'message': 'Signup Error',
                'error': f'{e}'
            }), 500
        else:
            flash(message='An error occurred during signup. Please try again.', category='danger')
            return render_template('signup.html', form=form if 'form' in locals() else SignupForm()), 500

@app.route('/activate/<token>')
@jwt_required()
@csrf.exempt
def activate_email(token):
    """
    Activate the user account
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    try:
        email = confirm_token(token)
        if email == current_user.email:
            user = userModel.User.query.filter_by(email=email).first_or_404()
            if user.activated:
                msg = 'Account already activated.'
                if postman_notebook_request:
                    return jsonify({"message": msg})
                flash(message=msg, category='success')
            else:
                user.activated = True
                user.activated_on = datetime.datetime.now()
                user.api_key = utils.generate_secret_key()
                user.client_secret = utils.generate_secret_key(True)
                db.session.add(user)
                db.session.commit()
                app.is_user_activated = True
                html = render_template('api-keys-email.html', api_key=user.api_key, client_secret=user.client_secret)
                subject = "API Keys"
                send_email(user.email, subject, html)
                msg = 'You have activated your account. API Keys are shared via email. Thanks!'
                if postman_notebook_request:
                    return jsonify({"message": msg})
                else:
                    flash(msg, 'success')
                    return make_response(redirect(url_for('logout')))
        else:
            msg = "Invalid activation link!"
            if postman_notebook_request:
                return jsonify({"message": msg})
            flash(message=msg, category='danger')
    except:
        msg = 'The confirmation link is invalid or has expired.'
        if postman_notebook_request:
            return jsonify({"message": msg})
        else:
            flash(message=msg, category='danger')
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
@csrf.exempt
def refresh():
    """
    We are using the `refresh=True` options in jwt_required to only allow
    refresh tokens to access this route.
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    if postman_notebook_request:
        resp = make_response(jsonify({"access token": access_token}))
    else:
        resp = make_response(redirect(request.referrer))
    user = userModel.User.query.filter_by(id=current_user.id).first()
    user.access_token = access_token
    db.session.commit()
    set_access_cookies(resp, access_token)
    return resp


@app.route('/update', methods=['GET', 'POST'])
@jwt_required()
@csrf.exempt
def update():
    try:
        user_agent = request.headers.get('User-Agent')
        postman_notebook_request = utils.check_non_web_user_agent(user_agent)
        app.config["WTF_CSRF_ENABLED"] = False
        form = UpdateForm()
        if form.email.data is None:
            form.email.data = current_user.email
        if form.phone_num.data is None:
            form.phone_num.data = current_user.phone_num
        if form.discoverable.data is None:
            form.discoverable.data = current_user.discoverable
        if form.password.data is None:
            form.password.data = ""
            form.confirm_pass.data = ""

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
                    if postman_notebook_request:
                        return jsonify({"message": json_msg})
                    else:
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
            if postman_notebook_request:
                if json_msg != "" and json_msg[0] == ".":
                    json_msg = json_msg[2:]
                    return jsonify({"message": json_msg}), 202
                return jsonify({'message': "Nothing to be updated"}), 200
        if postman_notebook_request:
            return jsonify({"message": "Form validation failed"}), 400
        return render_template('update.html', form=form)
    except Exception as e:
        return jsonify({
            'message': 'Update User Error',
            'error': f'{e}'
        }), 401


@app.route('/logout', methods=["GET"])
@jwt_required(refresh=True)
@csrf.exempt
def logout():
    """
    Endpoint for revoking the current users access token. Saved the unique
    identifier (jti) for the JWT into our database.
    """
    try:
        from_asset_registry = request.headers.get('X-FROM-ASSET-REGISTRY')
        user_agent = request.headers.get('User-Agent')
        postman_notebook_request = utils.check_non_web_user_agent(user_agent)
        user = userModel.User.query.filter_by(id=current_user.id).first()
        tokens = {'Authorization': 'Bearer ' + user.access_token, 'X-Refresh-Token': user.refresh_token}
        if not from_asset_registry:
            requests.get(app.config['ASSET_REGISTRY_BASE_URL'] + '/logout', headers=tokens)
        user.access_token = None
        user.refresh_token = None
        db.session.commit()
        if not postman_notebook_request:
            resp = make_response(redirect(app.config['DEVELOPMENT_BASE_URL']))
        else:
            resp = make_response(jsonify({"message": "Successfully logged out"}), 200)
        resp.set_cookie('access_token_cookie', '', expires=0)
        resp.set_cookie('refresh_token_cookie', '', expires=0)
        return resp
    except Exception as e:
        return jsonify({
            'message': 'User Registry Logout Error',
            'error': f'{e}'
        }), 400


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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
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
@csrf.exempt
def resend_confirmation():
    """
    Resend the account activation email
    """
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)
    user = userModel.User.query.filter_by(email=current_user.email).first_or_404()
    if user.activated:
        msg = 'Account already activated.'
        if postman_notebook_request:
            return jsonify({"message": msg})
        flash(message=msg, category='info')
        return redirect(url_for('home'))
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('activate_email', token=token, _external=True)
    print(confirm_url)
    html = render_template('activation-email.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    msg = 'A new confirmation email has been sent.'
    if postman_notebook_request:
        return jsonify({"message": msg})
    flash(msg, 'success')
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET'])
@jwt_required()
@csrf.exempt
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
@csrf.exempt
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


@app.route('/forgot-password', methods=['GET', 'POST'])
@jwt_required(optional=True)
@csrf.exempt
def forgot_password():
    app.config["WTF_CSRF_ENABLED"] = False
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)

    # check if already logged in
    user = get_identity_if_logedin()
    if user:
        if not postman_notebook_request:
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home')
        elif postman_notebook_request:
            return jsonify({'message': 'Already logged in'})

    form = ForgotForm()

    # POST
    if form.validate_on_submit():
        # gets email and password
        email = form.email.data

        # check account exists
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if user:
            # create email
            token = generate_confirmation_token(email)
            url = url_for('reset_password', token=token, _external=True)
            html = render_template('reset-email.html', reset_url=url)
            subject = 'Reset password'

            # send email
            send_email(email, subject, html)

            # response
            msg = 'A link to reset your password has been sent to your email!'
            if postman_notebook_request:
                return jsonify({"message": msg})
            else:
                flash(message=Markup(f'A password reset link has been sent to "{email}".'), category='info')
        else:
            # unregistered or unactivated account
            msg = 'Account does not exist!'
            if postman_notebook_request:
                return jsonify({"message": msg})
            else:
                flash(message=Markup(f'A user with email "{email}" does not exist.'), category='danger')

    # GET       
    return render_template('forgot-password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@jwt_required(optional=True)
@csrf.exempt
def reset_password(token):
    app.config["WTF_CSRF_ENABLED"] = False
    user_agent = request.headers.get('User-Agent')
    postman_notebook_request = utils.check_non_web_user_agent(user_agent)

    # check if already logged in
    user = get_identity_if_logedin()
    if user:
        if not postman_notebook_request:
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home')
        elif postman_notebook_request:
            return jsonify({'message': 'Already logged in'})

    try:
        # check if token is valid email
        email = confirm_token(token)

        # check if user exists
        user = userModel.User.query \
            .filter_by(email=email) \
            .first()
        if user:
            form = PasswordResetForm()
            # POST
            if form.validate_on_submit():
                # get new password
                password = form.password.data
                user_to_update = userModel.User.query.filter_by(email=email).first()

                # check for new and old password
                if check_password_hash(user_to_update.password, password):
                    flash('We\'re sorry, but the new password you entered is the same as your previous password.',
                          'danger')
                    return redirect(url_for("reset_password", token=token))

                user_to_update.password = generate_password_hash(password)
                db.session.commit()

                # response
                msg = 'Password updated succesfully!'
                if postman_notebook_request:
                    return jsonify({"message": msg})
                else:
                    flash(message=Markup(f'Password for email "{email}" has been updated.'), category='info')
                    return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/')

            # GET
            return render_template('reset-password.html', form=form)

    except:
        msg = 'The confirmation link is invalid or has expired.'
        if postman_notebook_request:
            return jsonify({"message": msg})
        else:
            flash(message=msg, category='danger')
            return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/forgot-password')


@app.route("/verify-api-secret-keys", methods=['GET'])
@csrf.exempt
def verify_api_secret_keys():
    """
    Verify if the API Key and the Client Secret are valid for a user
    """
    try:
        api_key = request.headers.get('API-KEY')
        client_secret = request.headers.get('CLIENT-SECRET')
        if not api_key or not client_secret:
            return make_response(jsonify({
                "message": "API Key and Client Secret are required."
            }), 400)
        record = userModel.User.query.filter_by(api_key=api_key, client_secret=client_secret).first()

        if record:
            return jsonify({'message': True})
        else:
            return jsonify({'message': False})
    except Exception as e:
        return jsonify({
            'message': 'Verify API Keys Error',
            'error': f'{e}'
        }), 401


@app.route("/generate-api-keys", methods=['GET'])
@csrf.exempt
@jwt_required()
def generate_api_keys():
    """
    Generates the API Key and Client Secret for the logged-in user
    Send email only if request is not from postman or notebook
    """
    try:
        user_agent = request.headers.get('User-Agent')
        postman_notebook_request = utils.check_non_web_user_agent(user_agent)
        user_fetched = userModel.User.query.filter_by(email=current_user.email).first()
        if user_fetched:
            user_fetched.api_key = utils.generate_secret_key()
            user_fetched.client_secret = utils.generate_secret_key(True)
            db.session.commit()
            if postman_notebook_request:
                return jsonify({
                    "Message": "Keys generated successfully",
                    "api_key": user_fetched.api_key,
                    "client_secret": user_fetched.client_secret
                }), 200
            else:
                html = render_template('api-keys-email.html', api_key=user_fetched.api_key, client_secret=user_fetched.client_secret)
                subject = "API Keys"
                send_email(user_fetched.email, subject, html)
                msg = 'API Keys are shared via email. Thanks!'
                flash(msg, 'success')
                return redirect(app.config['DEVELOPMENT_BASE_URL'] + '/home')
        else:
            return jsonify({
                "Message": "User not found!"
            }), 404

    except Exception as e:
        return jsonify({
            'message': 'Generating API Keys Error',
            'error': f'{e}'
        }), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
