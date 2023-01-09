from flask_wtf import FlaskForm
from wtforms import (StringField, BooleanField,
                     EmailField, PasswordField)
from wtforms.validators import InputRequired, Length, Email, DataRequired, EqualTo, Regexp


class SignupForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    phone_num = StringField('Phone Number', validators=[InputRequired()])
    password = PasswordField('New Password',
                             validators=[DataRequired(), Regexp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}", message="Please follow the guidelines for a strong password")])
    confirm_pass = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords "
                                                                                                           "don't "
                                                                                                           "match!")])

    newsletter = BooleanField('Subscribe to our newsletter', default='checked')
    discoverable = BooleanField('Do you want your profile to be discoverable?', default='checked')
