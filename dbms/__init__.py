import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_mail import Mail
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)
csrf = CSRFProtect(app)
app.is_user_activated = False  # global flag to check if user is activated

# Email config settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ['APP_MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['APP_MAIL_PASSWORD']
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

app.config.from_object(os.getenv('APP_SETTINGS'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["WTF_CSRF_ENABLED"] = True
db = SQLAlchemy(app)
