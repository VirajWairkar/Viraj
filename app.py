import os
from dotenv import load_dotenv
from datetime import date, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SelectField, DateField, FileField, TelField
from wtforms.validators import DataRequired, Length, Regexp
from wtforms import IntegerField, TextAreaField
import bleach

# ─── Flask setup ───
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── CSRF & DB ───
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# ─── Models ───
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    roles         = db.Column(db.String, nullable=False, default='')

class Report(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String, nullable=False)
    filename    = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    location    = db.Column(db.String, nullable=False)
    date_found  = db.Column(db.String, nullable=False)
    category    = db.Column(db.String, nullable=False)
    contact     = db.Column(db.String, nullable=False)
    timestamp   = db.Column(db.DateTime, server_default=db.func.now())
    claimed     = db.Column(db.Boolean, default=False)
    claimed_by  = db.Column(db.String, nullable=True)
    received    = db.Column(db.Boolean, default=False)

class ClaimRequest(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_email  = db.Column(db.String, nullable=False)
    report_id   = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    status      = db.Column(db.String, nullable=False, default='pending')
    timestamp   = db.Column(db.DateTime, server_default=db.func.now())
    report      = db.relationship('Report', backref=db.backref('claim_requests', lazy=True))

class Complaint(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    reporter_email = db.Column(db.String, nullable=False)
    report_id      = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    message        = db.Column(db.String, nullable=True)
    timestamp      = db.Column(db.DateTime, server_default=db.func.now())
    report         = db.relationship('Report', backref=db.backref('complaints', lazy=True))

# ─── Forms ───
class ReportForm(FlaskForm):
    description = StringField('Description', validators=[
        DataRequired(), Length(max=100),
        Regexp(r'^[A-Za-z0-9\s\.!\-]+$')
    ])
    location   = StringField('Location', validators=[
        DataRequired(), Length(max=50),
        Regexp(r'^[A-Za-z0-9\s,\-]+$')
    ])
    date_found = DateField('Date Found', validators=[DataRequired()], format='%Y-%m-%d')
    category   = SelectField('Category', validators=[DataRequired()], choices=[
        ('accessories','Accessories'),
        ('books','Books'),
        ('stationary','Stationary'),
        ('others','Others')
    ])
    contact    = TelField('Contact', validators=[
        DataRequired(), Length(max=20),
        Regexp(r'^[0-9\+\-\s]+$')
    ])
    photo      = FileField('Photo', validators=[DataRequired()])

class ComplaintForm(FlaskForm):
    report_id = IntegerField('Report ID', validators=[DataRequired()])
    details   = TextAreaField('Details', validators=[DataRequired()])

# ─── Helpers & Context ───
@app.context_processor
def inject_globals():
    return {
        'email': session.get('email'),
        'roles': session.get('roles', []),
        'today': date.today()
    }

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'email' not in session or 'admin' not in session.get('roles', []):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# ─── Routes ───
@app.route('/', endpoint='show_home')
def show_home():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    found_count = Report.query.filter_by(received=True).count()
    return render_template('home.html', found_count=found_count)

@app.route('/login', methods=['GET','POST'], endpoint='do_login')
def do_login():
    if request.method == 'POST':
        email = request.form['email']
        pwd   = request.form['password']
        user  = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, pwd):
            flash('Invalid credentials')
            return redirect(url_for('do_login'))
        session['email'] = user.email
        session['roles'] = user.roles.split(',') if user.roles else []
        return redirect(url_for('show_home'))
    return render_template('login.html')

@app.route('/logout', endpoint='logout')
def logout():
    session.clear()
    return redirect(url_for('do_login'))

# alias:
app.add_url_rule('/logout', endpoint='do_logout', view_func=logout)

@app.route('/report-found', methods=['GET','POST'])
def report_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    form = ReportForm()
    if form.validate_on_submit():
        f     = form.photo.data
        fname = secure_filename(f.filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        rpt = Report(
            email=session['email'],
            filename=fname,
            description=bleach.clean(form.description.data),
            location=bleach.clean(form.location.data),
            date_found=str(form.date_found.data),
            category=form.category.data,
            contact=bleach.clean(form.contact.data)
        )
        db.session.add(rpt)
        db.session.commit()
        flash('Report submitted.')
        return redirect(url_for('category_items', cat=form.category.data))
    max_d = date.today().isoformat()
    min_d = (date.today() - timedelta(days=6)).isoformat()
    return render_template('report_found.html', form=form, min_date=min_d, max_date=max_d)

@app.route('/category/<cat>')
def category_items(cat):
    if 'email' not in session:
        return redirect(url_for('do_login'))
    fdate = request.args.get('filter_date')
    base = Report.query.filter_by(category=cat, claimed=False)
    items = base.filter_by(date_found=fdate).all() if fdate else base.all()
    my_claims = {c.report_id for c in ClaimRequest.query.filter_by(user_email=session['email'])}
    return render_template('categoryitems.html',
                           items=items,
                           category=cat,
                           min_date=(date.today()-timedelta(6)).isoformat(),
                           max_date=date.today().isoformat(),
                           filter_date=fdate,
                           user_claims=my_claims)

@app.route('/items-found')
def items_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    found = Report.query.filter_by(received=True).order_by(Report.timestamp.desc()).all()
    return render_template('items_found.html', items=found)

@app.route('/request-claim/<int:report_id>', methods=['POST'])
def request_claim(report_id):
    if 'email' not in session:
        return jsonify(message='Not logged in'), 403
    exists = ClaimRequest.query.filter_by(
        user_email=session['email'],
        report_id=report_id
    ).first()
    if exists:
        return jsonify(message='Already pending'), 200
    cr = ClaimRequest(user_email=session['email'], report_id=report_id)
    db.session.add(cr)
    db.session.commit()
    return jsonify(message='Claim sent!'), 200

@app.route('/receive-report/<int:report_id>')
def receive_report(report_id):
    rpt = Report.query.get_or_404(report_id)
    if rpt.claimed_by == session.get('email'):
        rpt.received = True
        db.session.commit()
    return redirect(url_for('items_found'))

@app.route('/requests')
@admin_only
def view_requests():
    pending = ClaimRequest.query.filter_by(status='pending').all()
    grouped = {}
    for r in pending:
        grouped.setdefault(r.report_id, []).append(r)
    return render_template('requests.html', grouped_requests=grouped)

@app.route('/requests/<int:req_id>/<decision>', methods=['POST'])
@admin_only
def decide_claim(req_id, decision):
    cr = ClaimRequest.query.get_or_404(req_id)
    if decision == 'accept':
        cr.status = 'accepted'
        rpt = Report.query.get(cr.report_id)
        rpt.claimed = True
        rpt.claimed_by = cr.user_email
        for other in ClaimRequest.query.filter_by(report_id=cr.report_id):
            if other.id != cr.id:
                other.status = 'declined'
    else:
        cr.status = 'declined'
    db.session.commit()
    return redirect(url_for('view_requests'))

@app.route('/settings')
def settings():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    return render_template('settings.html')

# ─── DB Init & Seeding ───
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='alice@somaiya.edu').first():
        db.session.add(User(
            email='alice@somaiya.edu',
            password_hash=generate_password_hash('apple123'),
            roles='admin'
        ))
    if not User.query.filter_by(email='bob@somaiya.edu').first():
        db.session.add(User(
            email='bob@somaiya.edu',
            password_hash=generate_password_hash('banana@123'),
            roles=''
        ))
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
