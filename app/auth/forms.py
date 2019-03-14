from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, \
    SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                    Length(1,64),Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                    Length(1,64),Email()])
    submit = SubmitField('Reset')


class SetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', 
                        message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Submit')
    

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                    Length(1,64),Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
            message='Usernames must have only letters, numbers, '+
                'dots or underscores')
        ])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', 
                        message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PasswordChangeForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), EqualTo('new_password2', 
                        message='Passwords must match.')])
    new_password2 = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def validate_old_password(self, field):
        user = User.query.filter_by(username=current_user.username).first()
        print(f'user: {user.username}')
        if not user.verify_password(field.data):
            print('password is wrong')
            raise ValidationError('The Old password is wrong.')
    