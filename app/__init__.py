import os
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta


from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config.from_object(os.getenv('APP_SETTINGS'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BASE_URL'] = 'http://127.0.0.1:5000'  # Running on localhost
# If true this will only allow the cookies that contain your JWTs to be sent
# over https. In production, this should always be set to True
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(minutes=10)
# following must be made true in production
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
db = SQLAlchemy(app)

from app.models import user, blackList, domainCheck, tokenBlocklist

migrate = Migrate(app, db)
