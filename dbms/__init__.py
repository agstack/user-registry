import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_mail import Mail

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config.update(dict(
    DEBUG=True,
    MAIL_SERVER='smtp.mail.outlook.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.environ['APP_MAIL_USERNAME'],
    MAIL_PASSWORD=os.environ['APP_MAIL_PASSWORD'],
    MAIL_DEFAULT_SENDER='your@email.com'
))
mail = Mail(app)
app.config.from_object(os.getenv('APP_SETTINGS'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["WTF_CSRF_ENABLED"] = True
db = SQLAlchemy(app)
