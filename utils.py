import config
import requests
from itsdangerous import URLSafeTimedSerializer
from flask import url_for, render_template
from models import Option
from operator import itemgetter


def mailgun_send_message(subject, receivers, body, replyto=None, html=None):
    mailgun_api_domain = config.MAILGUN_DOMAIN_NAME
    domain_name = config.MAILGUN_DISPLAY_DOMAIN_NAME
    api_key = config.MAILGUN_API_KEY
    org_name = config.ORGANIZATION_NAME
    auth = ("api", api_key)
    data = {"from": "{0} <mail@{1}>".format(org_name, domain_name),
            "to": receivers,
            "subject": subject,
            "text": body}
    if replyto:
        data["h:Reply-To"] = replyto
    if html:
        data["html"] = html
    return requests.post(mailgun_api_domain, auth=auth, data=data)


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    return serializer.dumps(email, salt=config.SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    try:
        email = serializer.loads(
            token,
            salt=config.SECURITY_PASSWORD_SALT,
            max_age=expiration
        )
    except:
        return False
    return email


def send_invite(user, firstname):
    url = url_for('login', token=user.token, _external=True)
    email_html = render_template(
        "email_vote.html",
        u_id=user.email,
        vote_url=url)
    text = "Hi there {0},\n\nPlease click on the link below to vote on {1}. This vote will close on {2}.\n\n{3}\n\n--{4}".format(
        firstname, config.VOTE_DESCRIPTION, config.END_DATE_STR, url, config.ORGANIZATION_NAME)
    subject = config.ORGANIZATION_NAME + ": Please vote!"
    mailgun_send_message(subject, [user.email], text, html=email_html)


def current_results():
    try:
        options = Option.query.all()
        votes = {}
        for option in options:
            votes[option.name] = option.voters.filter_by(counting=True).count()
        sorted_votes = sorted(votes.items(), key=itemgetter(1), reverse=True)
        return sorted_votes
    except Exception as e:
        return str(e)


def choose_winners():
    try:
        options = Option.query.all()
        votes = {}
        for option in options:
            votes[str(option.id)] = option.voters.filter_by(
                counting=True).count()
        sorted_votes = sorted(votes.items(), key=itemgetter(1), reverse=True)
        limit = config.MAX_CHOICES
        out = []
        try:
            for x in range(limit):
                out.append(
                    Option.query.filter_by(
                        id=sorted_votes[x][0]).first().name)
        except IndexError:
            return out
        # accounts for ties
        tie_exists = False
        try:
            for x in range(limit, len(sorted_votes)):
                if sorted_votes[limit - 1][1] == sorted_votes[x][1]:
                    if not tie_exists:
                        out[len(out) - 1] = out[len(out) - 1] + " (tie)"
                        tie_exists = True
                    out.append(
                        Option.query.filter_by(
                            id=sorted_votes[x][0]).first().name +
                        " (tie)")
                else:
                    return out
        except IndexError:
            return out
        return out
    except Exception as e:
        return str(e)
