from flask_wtf import FlaskForm
from wtforms import (StringField, BooleanField, PasswordField)
from wtforms.validators import InputRequired, Email, DataRequired, EqualTo, Regexp, Optional


class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Please provide a valid email')])
    phone_num = StringField('Phone Number', validators=[DataRequired(), Regexp("^[0-9]{6,16}", message='Please '
                                                                                                       'provide a '
                                                                                                       'valid phone '
                                                                                                       'number (e.g. '
                                                                                                       '921234567890)')])
    password = PasswordField('New Password',
                             validators=[DataRequired(), Regexp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}", message="Please follow the guidelines for a strong password")])
    confirm_pass = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords "
                                                                                                           "don't "
                                                                                                           "match!")])

    newsletter = BooleanField('Subscribe to our newsletter', default='checked')
    discoverable = BooleanField('Do you want your profile to be discoverable?', default='checked')
    lng = StringField('lng', default='')
    lat = StringField('lat', default='')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Enter a valid email')])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    next = StringField('next')



class UpdateForm(FlaskForm):
    email = StringField('Email', validators=[Email(message='Please provide a valid email'), Optional()])
    phone_num = StringField('Phone Number', validators=[Regexp("^[0-9]{6,16}", message='Please '
                                                                                                       'provide a '
                                                                                                       'valid phone '
                                                                                                       'number (e.g. '
                                                                                                       '921234567890)'), Optional()])
    password = PasswordField('New Password',
                             validators=[Regexp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}",
                                                                message="Please follow the guidelines for a strong password"), Optional()])
    confirm_pass = PasswordField('Confirm Password',
                                 validators=[EqualTo('password', message="Passwords "
                                                                                         "don't "
                                                                                         "match!")])

    discoverable = BooleanField('Do you want your profile to be discoverable?')


class ForgotForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Enter a valid email')])
    
    
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password',
                             validators=[DataRequired(), Regexp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}", message="Please follow the guidelines for a strong password")])
    confirm_pass = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords "
                                                                                                           "don't "
                                                                                                           "match!")])