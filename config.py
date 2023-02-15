import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv()


class Config(object):
    SECRET_KEY = 'user_registry_secret_key'
    SECURITY_PASSWORD_SALT = 'user_registry_security_password_salt'
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    ASSET_REGISTRY_BASE_URL = os.getenv('ASSET_REGISTRY_BASE_URL')
    ASSET_REGISTRY_BASE_URL_FE = os.getenv('ASSET_REGISTRY_BASE_URL_FE')

    # mail settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    # gmail authentication
    MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

    # mail accounts
    MAIL_DEFAULT_SENDER = os.getenv('APP_MAIL_USERNAME')


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    DEVELOPMENT_BASE_URL = os.getenv('DEVELOPMENT_BASE_URL')


class TestingConfig(Config):
    TESTING = True
