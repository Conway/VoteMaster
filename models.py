from datetime import datetime
from flask.ext.sqlalchemy import SQLAlchemy
from flask_bcrypt import check_password_hash, generate_password_hash
import pyotp
import markdown

db = SQLAlchemy()


# many-to-many relationship helper table
selections = db.Table(
    'selections', db.Column(
        'vote_id', db.Integer, db.ForeignKey('Vote.id')), db.Column(
            'option_id', db.Integer, db.ForeignKey('Option.id')))


class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String)
    obfuscated_email = db.Column(db.String)
    token = db.Column(db.String, unique=True)
    in_timeout = db.Column(db.Boolean, default=False)
    vote = db.relationship('Vote', backref='user', lazy='dynamic')
    viewed_email = db.Column(db.Boolean, default=False)
    delivered_email = db.Column(db.Boolean, default=False)
    
    def __init__(self, email, token):
        self.email = email
        self.obfuscated_email = obfuscate_email(email)
        self.token = token
        self.in_timeout = False

    def set_email(self, email):
        self.email = email
        self.obfuscated_email = obfuscate_email(email)


class Admin(db.Model):
    __tablename__ = 'Admin'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    email = db.Column(db.String)
    pw_hash = db.Column(db.String)
    enabled = db.Column(db.Boolean)
    role = db.Column(db.Enum('full', 'normal', 'observer'))
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    actions = db.relationship("Action", backref="user")
    otp_enabled = db.Column(db.Boolean)
    otp_secret = db.Column(db.String)

    def __init__(
            self,
            name,
            email,
            password,
            enabled,
            role,
            confirmed=False,
            confirmed_on=None,
            otp_enabled=False):
        self.name = name
        self.email = email
        self.pw_hash = generate_password_hash(password, 10)
        self.enabled = enabled
        self.role = role
        self.confirmed = confirmed
        self.confirmed_on = confirmed_on
        self.otp_enabled = otp_enabled
        if otp_enabled:
            self.otp_secret = pyotp.random_base32()

    def set_pw(self, pw):
        self.pw_hash = generate_password_hash(pw, 10)

    def verify_pw(self, pw):
        return check_password_hash(self.pw_hash, pw)

    def confirm(self):
        self.confirmed = True
        self.confirmed_on = datetime.utcnow()

    def set_otp(self, reset=False):
        if self.otp_secret and not reset:
            return self.otp_secret
        otp_secret = pyotp.random_base32()
        self.otp_secret = otp_secret
        return otp_secret

    def verify_otp(self, token):
        if not self.otp_secret:
            raise ValueError
        totp = pyotp.TOTP(self.otp_secret)
        print("expected: " + totp.now())
        print("actual: " + token)
        return totp.verify(token)


class Option(db.Model):
    __tablename__ = 'Option'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    description_html = db.Column(db.String)
    # allows a candidate to be locked
    live = db.Column(db.Boolean, default=True)

    def update_description(self, description, md=True):
        self.description = description
        if md:
            self.description_html = markdown.markdown(description)
        else:
            self.description_html = description

class Vote(db.Model):
    __tablename__ = 'Vote'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner = db.Column(db.Integer, db.ForeignKey('User.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow())
    counting = db.Column(db.Boolean, default=True)
    votes = db.relationship(
        'Option',
        secondary=selections,
        backref=db.backref(
            'voters',
            lazy='dynamic'))


class Strings(db.Model):
    __tablename__ = 'Strings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    notes = db.Column(db.String, default="")
    about_text = db.Column(db.String, default="")
    email_message_text = db.Column(db.String, default="")
    vote_info = db.Column(db.String, default="")


class TimeSettings(db.Model):
    __tablename__ = 'Settings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    status = db.Column(db.Enum('open', 'closed'), default='open')
    close_message_text = db.Column(
        db.String, default="This vote is now closed")


class Action(db.Model):
    __tablename__ = 'Action'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner = db.Column(db.Integer, db.ForeignKey('Admin.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow())
    type = db.Column(
        db.Enum(
            'closeelection',
            'openelection',
            'enablevote',
            'disablevote',
            'updatenote',
            'createoption',
            'lockoption',
            'unlockoption',
            'inviteuser',
            'lockuser',
            'unlockuser',
            'approveadmin',
            'disableadmin',
            'createaccount',
            'changeadminrole',
            'enable2fa',
            'disable2fa'))
    target_type = db.Column(
        db.Enum(
            'admin',
            'user',
            'option',
            'settings',
            'vote'))
    text = db.Column(db.String)
    target_id = db.Column(db.Integer)


def obfuscate_email(email):
    idx = email.index("@")
    out = ''
    for x in range(idx):
        if x == 0 or x == idx - 1 or email[x] == '.':
            out += email[x]
        else:
            out += '*'
    for y in range(idx, len(email)):
        out += email[y]
    return out
