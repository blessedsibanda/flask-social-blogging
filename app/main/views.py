from datetime import datetime 
from flask import render_template, session, redirect, url_for, current_app
from flask_login import login_required
from .import main
from .forms import NameForm
from .. import db 
from ..models import User
from ..email import send_email


@main.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'

@main.route('/', methods=['GET','POST'])
def index():
    form = NameForm()
    users = User.query.all()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            db.session.commit()
            session['known'] = False
            if current_app.config['FLASKY_ADMIN']:
                send_email(current_app.config['FLASKY_ADMIN'],'New User',
                        'mail/new_user', user=user)
        else:
            session['known'] = True
        session['name'] = form.name.data 
        form.name.data = ''
        return redirect(url_for('.index'))
    return render_template('index.html', 
                            current_time=datetime.utcnow(),
                            name=session.get('name'),
                            form=form,
                            users=users,
                            known=session.get('known', False))