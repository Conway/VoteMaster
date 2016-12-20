from flask import abort, Flask, jsonify, url_for, redirect, render_template, Response, request, session, send_from_directory
from flask_weasyprint import HTML, render_pdf
from decorators import admin_required, site_enabled
from forms import ContactForm, LoginForm, RegistrationForm
from models import db, User, Admin, Option, Vote, Strings, TimeSettings, Action
from datetime import datetime
from urllib.parse import quote, quote_plus
from raven.contrib.flask import Sentry
import csv
import os
import random
import uuid
import utils
import time

app = Flask(__name__)
db.init_app(app)
app.config.from_object('config')
sentry = Sentry(app, dsn=app.config['SENTRY_URL'])



BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = '{0}{1}'.format(
    'sqlite:///', os.path.join(BASE_DIRECTORY, 'app.db'))


@app.before_first_request
def create_db():
    db.create_all()
    string_existing = Strings.query.first()
    if not string_existing:
        strings = Strings()
        db.session.add(strings)
        db.session.commit()
    else:
        app.config['NOTE'] = string_existing.notes
    time_settings = TimeSettings.query.first()
    if not time_settings:
        t_s = TimeSettings()
        db.session.add(t_s)
        db.session.commit()


@app.errorhandler(404)
def error_404(e):
    error = "Error 404: Page Not Found. Check the URL to make sure you typed it in right."
    return render_template("error.html", error=error), 404


@app.errorhandler(403)
def error_403(e):
    error = "Error 403: Forbidden.\nThis page is for logged in users only."
    return render_template("error.html", error=error), 403


@app.errorhandler(500)
def error_500(e):
    error = "Error 500: Internal Server Error"
    return render_template("error.html", error=error), 500

@app.route('/robots.txt')
def robots_dot_txt():
    return send_from_directory(app.static_folder, request.path[1:])

# Voter functions


@app.route('/')
def home():
    # Maybe a real homepage will come later
    return redirect(app.config['ORG_HOMEPAGE'])


@app.route('/redirect/<string:token>')
def login(token):
    session['referrer'] = request.referrer
    result = User.query.filter_by(token=token).first()
    if result and not result.vote.first():
        session['token'] = token
        session['email'] = result.email
        return redirect('/vote')
    elif result.vote.first():
        error = "Error: You have already voted"
        return render_template("error.html", error=error)
    return abort(404)


@app.route('/vote')
@site_enabled
def vote():
    try:
        token = session['token']
    except KeyError:
        error = "Please retrieve the link sent to you and vote from there. If you still have issues, make sure your cookies are enabled"
        return render_template("error.html", error=error)
    if not User.query.filter_by(token=token).first().vote.first():
        choices = Option.query.filter_by(live=True).all()
        choice_list = []
        for choice in choices:
            choice_list.append(choice)
        if app.config['RANDOMIZE_CHOICES']:
            random.shuffle(choice_list)
        limit = app.config['MAX_CHOICES']
        if not choices:
            return render_template(
                "error.html",
                error="The vote is not set up yet. Try again later")
        return render_template("vote.html", choices=choice_list, limit=limit)
    else:
        error = "You have already voted."
        return render_template("error.html", error=error)


@app.route('/api/record_vote')
@site_enabled
def api_record_vote():
    token = session['token']
    user = User.query.filter_by(token=token).first()
    if user.vote.first():
        return abort(403)
    choices = request.args.get('choices')
    choices_list = choices.split(',')
    choices_list = choices_list[:len(choices_list) - 1]  # remove the last item
    if len(choices_list) > app.config['MAX_CHOICES']:
        return abort(403)
    vote = Vote(owner=user.id)
    options_list = []
    for choice in choices_list:
        options_list.append(Option.query.filter_by(id=choice).first())
    vote.votes = options_list
    db.session.add(vote)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm(request.form)
    if request.method == "POST":
        error = not form.validate_on_submit()
    else:
        error = False
    if request.method == 'GET' or error:
        if 'email' in session.keys():
            form.email.data = session['email']
        return render_template("contact.html", form=form, error=error)
    else:
        email = form.email.data
        subject = "[{0} Help] ".format(
            app.config['SITE_NAME']) + form.subject.data
        message_prefix = "The following message was a help submission on {0}\n\n".format(
            app.config['SITE_NAME'])
        if request.headers.getlist("X-Forwarded-For"):
            ip = request.headers.getlist("X-Forwarded-For")[0]
        else:
            ip = request.remote_addr
        u_a = request.user_agent.string
        robot_food = "\n\nIP: {0}\n\nUser Agent: {1}\n\n".format(ip, u_a)
        robot_food += "Email Address: {0}\n\n".format(email)
        if 'email' in session.keys():
            robot_food += "Email Cookie: {0}".format(session['email'])
        message = message_prefix + form.message.data + robot_food
        utils.mailgun_send_message(
            subject,
            app.config['CONTACT_EMAILS'],
            message,
            replyto=email)
        message = "Your message was successfully sent"
        return render_template("success.html", message=message)


@app.route('/success')
def success():
    msg = "Your vote has been successfully recorded."
    return render_template("success.html", message=msg)

# admin functions


@app.route('/logout')
def clear_session():
    session.clear()
    return redirect('/admin')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' in session.keys() and session['admin']:
        admin = Admin.query.filter_by(email=session['user']).first()
        if admin.enabled and admin.confirmed or admin.role=='full':
            return redirect('/admin/dashboard')
        else:
            return render_template(
                "error.html",
                error="This account is not confirmed and/or not enabled")
    form = LoginForm(request.form)
    if request.method == "POST":
        error = not form.validate_on_submit()
    else:
        error = False
    if request.method == 'GET' or error:
        return render_template("login.html", form=form, error=error)
    else:
        email = form.email.data
        password = form.password.data
        user = Admin.query.filter_by(email=email).first()
        if user and user.verify_pw(password):
            session['user'] = user.email
            session['name'] = user.name
            if not user.otp_enabled:
                session['admin'] = True
                return redirect('/admin/dashboard')
            else:
                return redirect('/admin/otp')
            if user.role == 'observer':
                return redirect('/results')
            return redirect('/admin/dashboard')
        else:
            return render_template("login.html", form=form, error=error)


@app.route('/admin/dashboard')
@admin_required
def dashboard():
    data = {}
    data['winner'] = "".join(
        winner + ", " for winner in utils.choose_winners())
    data['winner'] = data['winner'][:len(data['winner']) - 2]
    data['received'] = Vote.query.count() or 0
    data['remaining'] = User.query.count() - Vote.query.count() or 0
    data['approved'] = Vote.query.filter_by(counting=True).count() or 0
    data['discarded'] = Vote.query.filter_by(counting=False).count() or 0
    return render_template("dashboard.html", data=data)

@app.route('/admin/me')
@admin_required
def admin_profile():
    admin = Admin.query.filter_by(email=session['user']).first()
    return render_template("me.html", admin=admin)

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST":
        error = not form.validate_on_submit()
    else:
        error = False
    if request.method == 'GET' or error:
        return render_template("registration.html", form=form, error=error)
    elif request.method == 'POST':
        email = form.email.data
        name = form.name.data
        password = form.password.data
        if Admin.query.first():
            role = 'normal'
            enabled = False
        else:
            role = 'full'
            enabled = True
        admin = Admin(name, email, password, enabled, role)
        token = utils.generate_confirmation_token(email)
        confirm_url = url_for('confirm', token=token, _external=True)
        html = render_template('confirmation_email.html',
                               confirm_url=confirm_url, admin=admin)
        message = "Hi there {0}!\n\nThanks for signing up. Please follow this link to activate your account:\n\n{1}\n\nCheers!".format(
            admin.name, confirm_url)
        subject = "Please confirm your email"
        utils.mailgun_send_message(subject, [email], message, html=html)
        db.session.add(admin)
        db.session.commit()
        message = "Please check your inbox for a confirmation email."
        return render_template("success.html", message=message)


@app.route('/confirm/<token>')
def confirm(token):
    try:
        email = utils.confirm_token(token)
    except:
        error = "Sorry, the confirmation link appears to be invalid."
        return render_template("error.html", error=error)
    admin = Admin.query.filter_by(email=email).first()
    if not admin:
        error = "Sorry, the confirmation link appears to be invalid."
        return render_template("error.html", error=error)
    if admin.confirmed:
        error = "Your account has already been verified."
        return render_template("error.html", error=error)
    else:
        admin.confirm()
        db.session.add(admin)
        db.session.commit()
        success = "Your account has been verified!"
        return render_template("success.html", message=success)


@app.route('/admin/manage/votes')
# @admin_required
def manage_vote():
    candidates = utils.current_results()
    votes = Vote.query.all()
    return render_template(
        "manage_votes.html",
        candidates=candidates,
        votes=votes)


@app.route('/admin/manage/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template("manage_users.html", users=users)


@app.route('/admin/manage/candidates')
# @admin_required
def manage_candidates():
    options = Option.query.all()
    total_votes = Vote.query.count() or 0
    return render_template("manage_candidates.html", options=options, total_votes=total_votes)


@app.route('/admin/manage/admins')
@admin_required
def manage_admins():
    current_admin_email = session['user']
    current_admin = Admin.query.filter_by(email=current_admin_email).first()
    if current_admin.role != 'full':
        return abort(403)
    admins = Admin.query.all()
    return render_template("manage_admins.html", admins=admins)


@app.route('/admin/manage/settings')
@admin_required
def manage_settings():
    t_zone = time.strftime("%z", time.gmtime())
    settings = TimeSettings.query.first()
    return render_template("manage_settings.html", time=t_zone,
                           settings=settings)


@app.route('/admin/export')
@admin_required
def export():
    return render_template("manage_export.html")


@app.route('/admin/log')
@admin_required
def admin_log():
    actions = Action.query.filter_by(
        **request.args.to_dict()).order_by(Action.id.desc()).all()
    return render_template("log.html", actions=actions)


@app.route('/results')
def view_results():
    if 'admin' in session.keys() and session['admin']:
        public = False
        user = session['name']
    elif app.config['PUBLIC_VALIDATION'] and ('admin' not in session.keys() or not session['admin']):
        public = True
        if request.headers.getlist("X-Forwarded-For"):
            user = request.headers.getlist("X-Forwarded-For")[0]
        else:
            user = request.remote_addr
    else:
        return abort(403)

    formatted_time = "Generated on %A, %B %d, %Y at %I:%M %p Server Time"
    time_str = datetime.today().strftime(formatted_time)

    results = utils.current_results()
    winners = utils.choose_winners()
    votes = Vote.query.all()
    return render_template("results.html", time=time_str, user=user,
                           candidates=results, winners=winners, votes=votes,
                           public=public)


@app.route('/admin/otp', methods=['GET', 'POST'])
def admin_otp():
    admin = Admin.query.filter_by(email=session['user']).first()
    if not admin:
        return render_template("error.html", error="You are not logged in")
    method = request.method
    if admin.otp_enabled:
        if method == 'GET':
            return render_template("otp.html", registration=False)
        elif method == 'POST':
            token = request.form['token']
            result = admin.verify_otp(token)
            if result:
                session['admin'] = True
                return redirect('/admin/dashboard')
            else:
                return render_template("otp.html", error=True)
    else:
        if method == 'GET':
            secret = admin.set_otp()
            db.session.commit()
            url = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}".format(
                quote(app.config['SITE_NAME']), admin.email, secret)
            encoded = quote_plus(url)
            return render_template("otp.html", registration=True, url=encoded)
        elif method == 'POST':
            token_to_check = request.form['token']
            password = request.form['password']
            token_verified = admin.verify_otp(token_to_check)
            password_verified = admin.verify_pw(password)
            if token_verified and password_verified:
                admin.otp_enabled = True
                action = Action(
                    owner=admin.id,
                    type='enable2fa',
                    target_type='admin',
                    text='Self-enabled 2FA',
                    target_id=admin.id)
                db.session.add(action)
                db.session.commit()
                session['admin'] = True
                return redirect('/admin/dashboard')
            else:
                secret = admin.otp_secret
                url = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}".format(
                    quote(app.config['SITE_NAME']), admin.email, secret)
                encoded = quote_plus(url)
                return render_template(
                    "otp.html", error=True, registration=True, url=encoded)

@app.route('/admin/reset_pw', methods=['GET', 'POST'])
@admin_required
def reset_pw():
    if request.method == 'GET':
        return render_template("reset_pw.html")
    elif request.method == 'POST':
        current_pw = request.form['current']
        new_pw = request.form['new']
        confirm = request.form['confirm']
        if new_pw != confirm:
            return abort(403)
        admin = Admin.query.filter_by(email=session['user']).first()
        if admin.verify_pw(current_pw):
            admin.set_pw(new_pw)
        db.session.commit()
        return redirect("/admin/dashboard")


# Admin API

@app.route('/api/mailgun_event', methods=['GET', 'POST'])
def api_mailgun_event():
    event = request.args.get('event')
    event = str(event).lower()
    if event == 'opened':
        recipient = request.form['recipient']
        user = User.query.filter_by(email=recipient).first()
        user.viewed_email = True
        db.session.commit()
        return jsonify(status="OK")
    elif event == 'delivered':
        recipient = request.form['recipient']
        user = User.query.filter_by(email=recipient).first()
        user.delivered_email = True
        db.session.commit()
        return jsonify(status="OK")
    else:
        return jsonify(status="ERROR"), 406


@app.route('/api/send_email')
@admin_required
def api_send_email():
    subject = request.args.get('subject')
    receivers = [request.args.get('receivers')]
    body = request.args.get('body')
    utils.mailgun_send_message(subject, receivers, body)
    return jsonify(status="OK")


@app.route('/api/disable_vote')
@admin_required
def api_cancel_vote():
    id = request.args.get('id')
    vote = Vote.query.filter_by(id=id).first()
    vote.counting = False
    db.session.commit()
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='disablevote',
        target_type='vote',
        text='Cancelled vote by {0}'.format(
            vote.user.email),
        target_id=vote.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/enable_vote')
@admin_required
def api_enable_vote():
    id = request.args.get('id')
    vote = Vote.query.filter_by(id=id).first()
    vote.counting = True
    db.session.commit()
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='enablevote',
        target_type='vote',
        text='Approved vote by {0}'.format(
            vote.user.email),
        target_id=vote.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/update_note')
@admin_required
def api_update_note():
    strings = Strings.query.first()
    text = request.args.get('text')
    strings.note = text
    app.config['NOTE'] = text
    db.session.commit()
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(owner=current_user.id, type='updatenote',
                    target_type='settings', text='Updated admin note',
                    target_id=1)  # the settings objects only have 1 id - 1
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/create_option')
@admin_required
def api_create_option():
    name = request.args.get('name')
    description = request.args.get('description')
    option = Option(name=name)
    option.update_description(description)
    db.session.add(option)
    db.session.commit()
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='createoption',
        target_type='option',
        text='created option ({0})'.format(name),
        target_id=option.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/lock_option')
@admin_required
def api_lock_option():
    id = request.args.get('id')
    option = Option.query.filter_by(id=id).first()
    option.live = False
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='lockoption',
        target_type='option',
        text='locked option ({0})'.format(
            option.name),
        target_id=option.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/unlock_option')
@admin_required
def api_unlock_option():
    id = request.args.get('id')
    option = Option.query.filter_by(id=id).first()
    option.live = True
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='unlockoption',
        target_type='option',
        text='unlocked option ({0})'.format(
            option.name),
        target_id=option.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/lock_user')
@admin_required
def api_lock_user():
    id = request.args.get('id')
    user = User.query.filter_by(id=id).first()
    user.in_timeout = True
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='lockuser',
        target_type='user',
        text='Locked user ({0})'.format(
            user.email),
        target_id=user.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/unlock_user')
@admin_required
def api_unlock_user():
    id = request.args.get('id')
    user = User.query.filter_by(id=id).first()
    user.in_timeout = False
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='lockuser',
        target_type='user',
        text='Unlocked user ({0})'.format(
            user.email),
        target_id=user.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/invite_user')
@admin_required
def api_invite_user():
    email = request.args.get('email')
    token = str(uuid.uuid4())
    user = User(email, token)
    db.session.add(user)
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='inviteuser',
        target_type='user',
        text='Invited user ({0})'.format(
            user.email),
        target_id=user.id)
    db.session.add(action)
    db.session.commit()
    try:
        send_email = request.args.get('send_email')
    except:
        return jsonify(status="OK")
    if send_email or send_email == 'true':
        url = url_for('login', token=token, _external=True)
        email_html = render_template(
            "email_vote.html", u_id=email, vote_url=url)
        text = "Hi there {0},\n\nPlease click on the link below to vote on {1}. This vote will close on {2}.\n\n{3}\n\n--{4}".format(
            email, app.config['VOTE_DESCRIPTION'], app.config['END_DATE_STR'], url, app.config['ORGANIZATION_NAME'])
        subject = app.config['ORGANIZATION_NAME'] + ": Please vote!"
        utils.mailgun_send_message(subject, [email], text, html=email_html)
    return jsonify(status="OK")

@app.route('/api/resend_invite')
@admin_required
def api_resend_invite():
    id = request.args.get('id')
    user = User.query.filter_by(id=id).first()
    url = url_for('login', token=user.token, _external=True)
    email_html = render_template("email_vote.html", u_id=user.email, vote_url=url)
    text = "Hi there {0},\n\nPlease click on the link below to vote on {1}. This vote will close on {2}.\n\n{3}\n\n--{4}".format(user.email, app.config['VOTE_DESCRIPTION'], app.config['END_DATE_STR'], url, app.config['ORGANIZATION_NAME'])
    subject = app.config['ORGANIZATION_NAME'] + ": Please vote!"
    utils.mailgun_send_message(subject, [user.email], text, html=email_html)
    return jsonify(status="OK")

@app.route('/api/disable_admin')
@admin_required
def api_disable_admin():
    current_admin = Admin.query.filter_by(email=session['user']).first()
    # only full permission can change roles
    if current_admin.role != 'full':
        return abort(403)
    id = request.args.get('id')
    admin = Admin.query.filter_by(id=id).first()
    admin.enabled = False
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(
        owner=current_user.id,
        type='disableadmin',
        target_type='admin',
        text='Disabled admin ({0})'.format(
            admin.name),
        target_id=admin.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/enable_admin')
@admin_required
def api_enable_admin():
    current_admin = Admin.query.filter_by(email=session['user']).first()
    # only full permission can change roles
    if current_admin.role != 'full':
        return abort(403)
    id = request.args.get('id')
    admin = Admin.query.filter_by(id=id).first()
    admin.enabled = True
    action = Action(
        owner=current_admin.id,
        type='approveadmin',
        target_type='admin',
        text='Enabled admin ({0})'.format(
            admin.name),
        target_id=admin.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/change_admin_role')
@admin_required
def api_change_admin_role():
    current_admin = Admin.query.filter_by(email=session['user']).first()
    if current_admin.role != 'full':
        return abort(403)
    role = request.args.get('role')
    if role not in ['full', 'normal', 'observer']:
        raise ValueError("Invalid Role")
    id = request.args.get('id')
    admin = Admin.query.filter_by(id=id).first()
    old_role = admin.role
    admin.role = role
    action = Action(owner=current_admin.id,
                    type='changeadminrole',
                    target_type='admin',
                    text="Changed {0}'s admin role ({1} -> {2})".format(admin.name,
                                                                        old_role,
                                                                        role),
                    target_id=admin.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/pdf_results')
@admin_required
def api_pdf_results():
    user = session['name']
    public = False
    formatted_time = "Generated on %A, %B %d, %Y at %I:%M %p Server Time"
    time_str = datetime.today().strftime(formatted_time)
    results = utils.current_results()
    winners = utils.choose_winners()
    votes = Vote.query.all()
    t_s = TimeSettings.query.first()
    alert = t_s.status == 'open'
    vote_html = render_template("pdf_results.html", time=time_str, user=user,
                                candidates=results, winners=winners,
                                votes=votes, public=public, alert=alert)
    return render_pdf(HTML(string=vote_html))


@app.route('/api/csv_votes')
@admin_required
def api_csv_votes():
    return Response(generate(), mimetype='text/csv')


@app.route('/api/bulk_invite', methods=['GET', 'POST'])
@admin_required
def api_bulk_invite():
    if 'file' not in request.files:
        return abort(403)
    file = request.files['file']
    from io import StringIO
    csvf = StringIO(file.read().decode())
    reader = csv.DictReader(csvf, delimiter=',')
    current_user = Admin.query.filter_by(email=session['user']).first()
    for line in reader:
        token = str(uuid.uuid4())
        user = User(line['E-mail 1 - Value'], token)
        db.session.add(user)
        action = Action(
            owner=current_user.id,
            type='inviteuser',
            target_type='user',
            text='Invited user ({0})'.format(
                user.email),
            target_id=user.id)
        db.session.add(action)
        db.session.commit()
        utils.send_invite(user, line['Given Name'])
    return jsonify(status="OK")


@app.route('/api/open_vote')
@admin_required
def api_open_vote():
    t_settings = TimeSettings.query.first()
    t_settings.status = 'open'
    db.session.add(t_settings)
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(owner=current_user.id, type='openelection',
                    target_type='settings', text='Opened election',
                    target_id=1)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/close_vote')
@admin_required
def api_close_vote():
    t_settings = TimeSettings.query.first()
    t_settings.status = 'closed'
    db.session.add(t_settings)
    current_user = Admin.query.filter_by(email=session['user']).first()
    action = Action(owner=current_user.id, type='closeelection',
                    target_type='settings', text='Closed election',
                    target_id=1)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


@app.route('/api/disable_2fa')
@admin_required
def api_disable_2fa():
    current_admin = Admin.query.filter_by(email=session['user']).first()
    if current_admin.role != 'full':
        return abort(403)
    id = request.args.get('id')
    admin = Admin.query.filter_by(id=id).first()
    admin.otp_enabled = False
    admin.otp_secret = None
    action = Action(owner=current_admin.id,
                    type='disable2fa',
                    target_type='admin',
                    text="Disabled 2FA on {0}".format(admin.name),
                    target_id=admin.id)
    db.session.add(action)
    db.session.commit()
    return jsonify(status="OK")


def generate():
    yield "id, owner, ip, date, ref, fingerprint, couting, votes\n"
    with app.app_context():
        rows = Vote.query.all()
        for row in rows:
            id = row.id
            owner = User.query.filter_by(id=row.owner).first().email
            ip = row.ip
            date = row.date
            ref = row.ref
            fingerprint = row.fingerprint
            counting = row.counting
            votes = ""
            for vote in row.votes:
                votes += vote.name + "/"
            yield "{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}\n".format(id, owner, ip, date, ref, fingerprint, counting, votes)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
    
