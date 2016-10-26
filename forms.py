from flask.ext.wtf import Form, RecaptchaField
from wtforms import PasswordField, SelectField, SubmitField, TextField, TextAreaField, validators
from wtforms.fields.html5 import EmailField


class LoginForm(Form):
    email = EmailField("Email", [validators.Email()])
    password = PasswordField("Password", [validators.Required()])
    recaptcha = RecaptchaField()
    submit = SubmitField("Login")


class RegistrationForm(Form):
    name = TextField("Name", [validators.Required()])
    email = EmailField("Email", [validators.Email()])
    password = PasswordField('Password', [
        validators.Required(),
        validators.EqualTo('confirm',
                           message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    recaptcha = RecaptchaField()
    submit = SubmitField("Submit")


class ContactForm(Form):
    email = EmailField("Email", [validators.Email()])
    subject = SelectField(
        "Subject",
        choices=[
            ('Voting Help',
             'Voting Help'),
            ('Account Help',
             'Account Help'),
            ('Bug/Error',
             'Bug/Error')])
    message = TextAreaField("Message", [validators.Required()])
    recaptcha = RecaptchaField([validators.Required()])
    submit = SubmitField("Submit")
