import os
from dotenv import load_dotenv

# ─── Load variables from .env into os.environ ───
load_dotenv()

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
from wtforms import StringField, SelectField, DateField, FileField, TelField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp
import bleach

from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)

# ─── Pull SECRET_KEY and DATABASE_URL from environment ───
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# ───── File upload folder ─────
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ───── CSRF Protection ─────
csrf = CSRFProtect(app)

# ───── Database setup ─────
db = SQLAlchemy(app)


# ───── Context Processor ─────
@app.context_processor
def inject_globals():
    return {
        'email': session.get('email'),
        'roles': session.get('roles', []),
        'today': date.today()
    }


# ───── (Optional) Google OAuth ─────
google_bp = make_google_blueprint(
    client_id="YOUR_GOOGLE_CLIENT_ID",
    client_secret="YOUR_GOOGLE_SECRET",
    scope=["profile", "email"],
    redirect_url="/google_callback"
)
app.register_blueprint(google_bp, url_prefix="/login")


# ───── Models ─────
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    roles         = db.Column(db.String, nullable=False, default='')  # e.g. "admin"


class Report(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String, nullable=False)
    filename    = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    location    = db.Column(db.String, nullable=False)
    date_found  = db.Column(db.String, nullable=False)  # 'YYYY-MM-DD'
    category    = db.Column(db.String, nullable=False)
    contact     = db.Column(db.String, nullable=False)
    timestamp   = db.Column(db.DateTime, server_default=db.func.now())
    claimed     = db.Column(db.Boolean, default=False)
    claimed_by  = db.Column(db.String, nullable=True)
    received    = db.Column(db.Boolean, default=False)


class Complaint(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    reporter_email = db.Column(db.String, nullable=False)
    report_id      = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    message        = db.Column(db.String, nullable=True)
    timestamp      = db.Column(db.DateTime, server_default=db.func.now())
    report         = db.relationship('Report', backref=db.backref('complaints', lazy=True))


class ClaimRequest(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_email  = db.Column(db.String, nullable=False)
    report_id   = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    status      = db.Column(db.String, nullable=False, default='pending')
    timestamp   = db.Column(db.DateTime, server_default=db.func.now())
    report      = db.relationship('Report', backref=db.backref('claim_requests', lazy=True))


# ───── New: Badges ─────
class Badge(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String, unique=True, nullable=False)
    threshold = db.Column(db.Integer, nullable=False)   # e.g. 5, 10, 20 returns


class UserBadge(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    badge_id  = db.Column(db.Integer, db.ForeignKey('badge.id'), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    user      = db.relationship('User', backref='user_badges')
    badge     = db.relationship('Badge')


# ───── Forms ─────
class ReportForm(FlaskForm):
    description = StringField(
        'Description',
        validators=[
            DataRequired(),
            Length(max=100),
            Regexp(r'^[A-Za-z0-9\s\.!\-]+$')
        ]
    )
    location = StringField(
        'Location',
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(r'^[A-Za-z0-9\s,\-]+$')
        ]
    )
    date_found = DateField('Date Found', validators=[DataRequired()], format='%Y-%m-%d')
    category = SelectField(
        'Category',
        validators=[DataRequired()],
        choices=[
            ('accessories','Accessories'),
            ('books','Books'),
            ('stationary','Stationary'),
            ('others','Others')
        ]
    )
    contact = TelField(
        'Contact',
        validators=[
            DataRequired(),
            Length(max=20),
            Regexp(r'^[0-9\+\-\s]+$')
        ]
    )
    photo = FileField('Photo', validators=[DataRequired()])


class ComplaintForm(FlaskForm):
    report_id = IntegerField('Item Report ID', validators=[DataRequired()])
    details   = TextAreaField('Complaint Details', validators=[DataRequired()])


# ───── Utility: Admin-only decorator ─────
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('do_login'))
        if 'admin' not in session.get('roles', []):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ───── ROUTES ─────

@app.route('/')
def show_home():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    # count total received
    found_count = Report.query.filter_by(received=True).count()
    return render_template('home.html', found_count=found_count)


@app.route('/login', methods=['GET','POST'], endpoint='do_login')
def do_login():
    if request.method == 'POST':
        email = request.form.get('email')
        pw    = request.form.get('password')
        user  = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, pw):
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

# Alias for templates that use 'do_logout'
app.add_url_rule('/logout', endpoint='do_logout', view_func=logout)


@app.route('/report-found', methods=['GET','POST'])
def report_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    form = ReportForm()
    if form.validate_on_submit():
        file = form.photo.data
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.',1)[-1].lower()
        if ext not in {'png','jpg','jpeg','gif'} or not file.mimetype.startswith('image/'):
            flash('Only image files allowed.')
            return redirect(url_for('report_found'))
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        rpt = Report(
            email=session['email'],
            filename=filename,
            description=bleach.clean(form.description.data),
            location=bleach.clean(form.location.data),
            date_found=str(form.date_found.data),
            category=form.category.data,
            contact=bleach.clean(form.contact.data)
        )
        db.session.add(rpt)
        db.session.commit()
        flash('Report submitted successfully.')
        return redirect(url_for('category_items', cat=form.category.data))

    max_date = date.today().isoformat()
    min_date = (date.today()-timedelta(days=6)).isoformat()
    return render_template(
        'report_found.html',
        form=form,
        min_date=min_date,
        max_date=max_date
    )


@app.route('/category/<cat>')
def category_items(cat):
    if 'email' not in session:
        return redirect(url_for('do_login'))
    filter_date = request.args.get('filter_date')
    base = Report.query.filter_by(category=cat, claimed=False)
    items = base.filter_by(date_found=filter_date).all() if filter_date else base.all()
    max_date = date.today().isoformat()
    min_date = (date.today()-timedelta(days=6)).isoformat()
    user_claims = {c.report_id for c in ClaimRequest.query.filter_by(user_email=session['email']).all()}
    return render_template(
        'categoryitems.html',
        items=items,
        category=cat,
        min_date=min_date,
        max_date=max_date,
        filter_date=filter_date,
        user_claims=user_claims
    )


@app.route('/items-found')
def items_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    all_reports = Report.query.filter_by(received=True).order_by(Report.timestamp.desc()).all()
    return render_template('items_found.html', items=all_reports)


@app.route('/claim/<int:report_id>')
def claim_report(report_id):
    if 'email' not in session:
        return redirect(url_for('do_login'))
    rpt = Report.query.get_or_404(report_id)
    if not rpt.claimed:
        rpt.claimed    = True
        rpt.claimed_by = session['email']
        db.session.commit()
        flash('Claim request sent!')
    return redirect(request.referrer or url_for('show_home'))


@app.route('/receive-report/<int:report_id>')
def receive_report(report_id):
    rpt = Report.query.get_or_404(report_id)
    if rpt.claimed_by == session.get('email') and not rpt.received:
        rpt.received = True
        db.session.commit()

        # ── Award badges ──
        user = User.query.filter_by(email=rpt.claimed_by).first()
        if user:
            count = Report.query.filter_by(claimed_by=user.email, received=True).count()
            badge = Badge.query.filter_by(threshold=count).first()
            if badge:
                exists = UserBadge.query.filter_by(user_id=user.id, badge_id=badge.id).first()
                if not exists:
                    db.session.add(UserBadge(user_id=user.id, badge_id=badge.id))
                    db.session.commit()
                    flash(f'🎉 Congrats! You earned the “{badge.name}” badge.')

    return redirect(url_for('category_items', cat=rpt.category))


@app.route('/requests')
@admin_only
def view_requests():
    pending = ClaimRequest.query.filter_by(status='pending').order_by(ClaimRequest.report_id).all()
    # group by report_id
    grouped = {}
    for r in pending:
        grouped.setdefault(r.report_id, []).append(r)
    return render_template('requests.html', grouped_requests=grouped)


@app.route('/requests/<int:req_id>/<decision>', methods=['POST'])
@admin_only
def decide_claim(req_id, decision):
    cr = ClaimRequest.query.get_or_404(req_id)
    cr.status = 'accepted' if decision=='accept' else 'declined'
    # if accept → mark report claimed=True/received=False
    if decision=='accept':
        rpt = cr.report
        rpt.claimed = True
        rpt.claimed_by = cr.user_email
    db.session.commit()
    flash(f'Request {decision}ed.')
    return redirect(url_for('view_requests'))


@app.route('/complaint/<int:report_id>')
def new_complaint(report_id):
    if 'email' not in session:
        return redirect(url_for('do_login'))
    report = Report.query.get_or_404(report_id)
    form = ComplaintForm()
    form.report_id.data = report.id
    return render_template('complaint_form.html', form=form, report=report)


@app.route('/complaint', methods=['POST'])
def submit_complaint():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    form = ComplaintForm()
    if form.validate_on_submit():
        c = Complaint(
            reporter_email=session['email'],
            report_id=form.report_id.data,
            message=form.details.data
        )
        db.session.add(c)
        db.session.commit()
        flash('Complaint submitted.')
        return redirect(url_for('show_home'))
    return redirect(url_for('show_home'))


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


# ───── Create DB & Seed Admin, Users, Badges ─────
with app.app_context():
    db.create_all()

    # Seed badges
    badge_defs = [
        ('5 Items Returned', 5),
        ('10 Items Returned', 10),
        ('Top Finder', 20)
    ]
    for name, thr in badge_defs:
        if not Badge.query.filter_by(name=name).first():
            db.session.add(Badge(name=name, threshold=thr))

    # Seed admin Alice
    if not User.query.filter_by(email='alice@somaiya.edu').first():
        db.session.add(User(
            email='alice@somaiya.edu',
            password_hash=generate_password_hash('apple123'),
            roles='admin'
        ))

    # Seed user Bob
    if not User.query.filter_by(email='bob@somaiya.edu').first():
        db.session.add(User(
            email='bob@somaiya.edu',
            password_hash=generate_password_hash('banana@123'),
            roles=''
        ))

    db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)
