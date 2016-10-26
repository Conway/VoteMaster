from functools import wraps
from flask import redirect, session, render_template
from models import Admin, TimeSettings


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            admin = Admin.query.filter_by(email=session['user']).first()
            if admin.role != 'full' and (
                    admin.confirmed == False or admin.enabled == False):
                return redirect('/admin')
            elif not session['admin']:
                return redirect('/admin')
            elif admin.role == 'observer':
                return redirect('/admin')
            else:
                return f(*args, **kwargs)
        except:
            return redirect('/admin')
    return wrapped


def site_enabled(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            t_settings = TimeSettings.query.first()
            if t_settings.status == 'closed':
                error = "Sorry, this vote is not currently accepting votes."
                return render_template("error.html", error=error)
            else:
                return f(*args, **kwargs)
        except:
            error = "Sorry, this vote is not currently accepting votes."
            return render_template("error.html", error=error)
    return wrapped
