import os
from dotenv import load_dotenv

# ─── Load variables from .env into os.environ ───
load_dotenv()

from datetime import date, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SelectField, DateField, FileField, TelField
from wtforms.validators import DataRequired, Length, Regexp

import bleach  # Make sure bleach is installed in your environment

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


# ───── Context Processor: make `email` and `today` available in every template ─────
@app.context_processor
def inject_globals():
    return {
        'email': session.get('email'),
        'roles': session.get('roles', []),
        'today': date.today()
    }


# ───── (Optional) Flask-Dance Google OAuth setup ─────
google_bp = make_google_blueprint(
    client_id="1017920286075-nv4i0bosqqr2kbf6mosmhj9ampbugkao.apps.googleusercontent.com",
    client_secret="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",
    scope=["profile", "email"],
    redirect_url="/google_callback"
)
app.register_blueprint(google_bp, url_prefix="/login")


# ───── Models ─────
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)  # ← Use this field
    roles         = db.Column(db.String, nullable=False, default='')  # e.g. "admin"


class Report(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String, nullable=False)
    filename    = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    location    = db.Column(db.String, nullable=False)
    date_found  = db.Column(db.String, nullable=False)  # stored as 'YYYY-MM-DD'
    category    = db.Column(db.String, nullable=False)
    contact     = db.Column(db.String, nullable=False)
    timestamp   = db.Column(db.DateTime, default=date.today)
    claimed     = db.Column(db.Boolean, default=False)


# ───── Forms ─────
class ReportForm(FlaskForm):
    description = StringField(
        'Description',
        validators=[
            DataRequired(),
            Length(max=100),
            Regexp(
                r'^[A-Za-z0-9\s\.!\-]+$',
                message="Only letters, numbers, spaces, and basic punctuation (.!-) allowed."
            )
        ]
    )
    location = StringField(
        'Location',
        validators=[
            DataRequired(),
            Length(max=50),
            Regexp(
                r'^[A-Za-z0-9\s,\-]+$',
                message="Only letters, numbers, spaces, commas, and dashes allowed."
            )
        ]
    )
    date_found = DateField(
        'Date Found',
        validators=[DataRequired()],
        format='%Y-%m-%d'
    )
    category = SelectField(
        'Category',
        validators=[DataRequired()],
        choices=[
            ('accessories', 'Accessories'),
            ('books',       'Books'),
            ('stationary',  'Stationary'),
            ('others',      'Others')
        ]
    )
    contact = TelField(
        'Contact',
        validators=[
            DataRequired(),
            Length(max=20),
            Regexp(
                r'^[0-9\+\-\s]+$',
                message="Only digits, plus, minus, and spaces allowed."
            )
        ]
    )
    photo = FileField(
        'Photo',
        validators=[DataRequired()]
    )


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
    # Currently protected: only logged-in users see home
    if 'email' not in session:
        return redirect(url_for('do_login'))
    return render_template('home.html')


# ───── LOGIN endpoint named “do_login” ─────
@app.route('/login', methods=['GET', 'POST'], endpoint='do_login')
def do_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Look up the user by email
        user = User.query.filter_by(email=email).first()

        # ── Combined check: if user doesn’t exist OR password is wrong, show generic message ──
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials')
            return redirect(url_for('do_login'))

        # ── Successful login: set session and redirect to home ──
        session['email'] = user.email
        session['roles'] = user.roles.split(',') if user.roles else []
        return redirect(url_for('show_home'))

    # If GET request, just render the login form
    return render_template('login.html')


@app.route('/logout', endpoint='logout')
def logout():
    session.clear()
    return redirect(url_for('do_login'))

# Alias '/logout' to 'do_logout' as well (some templates might use do_logout)
app.add_url_rule('/logout', endpoint='do_logout', view_func=logout)


@app.route('/report-found', methods=['GET', 'POST'])
def report_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))

    form = ReportForm()
    if form.validate_on_submit():
        # 1. Grab the uploaded file
        file = form.photo.data

        # 2. Immediately define `filename`
        filename = secure_filename(file.filename)

        # 3. Check file extension
        allowed_ext = {'png', 'jpg', 'jpeg', 'gif'}
        if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_ext:
            flash('Only images (png, jpg, jpeg, gif) are allowed.')
            return redirect(url_for('report_found'))

        # 4. Check MIME type
        if not file.mimetype.startswith('image/'):
            flash('Uploaded file is not an image.')
            return redirect(url_for('report_found'))

        # 5. Save the file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 6. Sanitize text inputs
        clean_desc    = bleach.clean(form.description.data)
        clean_loc     = bleach.clean(form.location.data)
        clean_contact = bleach.clean(form.contact.data)

        # 7. Create and store the report
        report = Report(
            email=session['email'],
            filename=filename,
            description=clean_desc,
            location=clean_loc,
            date_found=str(form.date_found.data),
            category=form.category.data,
            contact=clean_contact
        )
        db.session.add(report)
        db.session.commit()

        flash('Report submitted successfully.')
        return redirect(url_for('category_items', cat=form.category.data))

    # ─── Calculate date range for last 7 days ───
    max_date = date.today().isoformat()                        # today, e.g. "2025-06-06"
    min_date = (date.today() - timedelta(days=6)).isoformat()   # 6 days ago, e.g. "2025-05-31"

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

    # 1) Read `filter_date` from the query string (if provided).
    filter_date = request.args.get('filter_date', None)
    #    e.g. filter_date == "2025-06-03" if user picked June 3, 2025.

    # 2) Build the base query: unclaimed items in this category.
    base_query = Report.query.filter_by(category=cat, claimed=False)

    # 3) If a date was selected, restrict to that date:
    if filter_date:
        # We store `date_found` as 'YYYY-MM-DD', so this matches exactly.
        items = base_query.filter_by(date_found=filter_date).all()
    else:
        # No date filter → fetch all unclaimed items in this category.
        items = base_query.all()

    # 4) Compute the allowed range for the date picker:
    max_date = date.today().isoformat()                       # today, e.g. "2025-06-06"
    min_date = (date.today() - timedelta(days=6)).isoformat()  # six days ago, e.g. "2025-05-31"

    # 5) Render template, passing:
    #    • items         → the (possibly filtered) list of reports
    #    • category      → which category we’re viewing
    #    • min_date      → earliest selectable date (six days ago)
    #    • max_date      → latest selectable date (today)
    #    • filter_date   → the date the user has chosen (or None)
    return render_template(
        'categoryitems.html',
        items=items,
        category=cat,
        min_date=min_date,
        max_date=max_date,
        filter_date=filter_date
    )

@app.route('/items-found')
def items_found():
    if 'email' not in session:
        return redirect(url_for('do_login'))

    # 1) Fetch all unclaimed items (sorted newest-first)
    all_reports = Report.query.filter_by(claimed=False).order_by(Report.timestamp.desc()).all()

    # 2) Identify which users are admins (so template can show/hide delete buttons)
    admin_users = User.query.filter(User.roles.contains('admin')).all()
    admin_emails = [u.email for u in admin_users]

    # 3) Render the items_found.html template
    return render_template(
        'items_found.html',
        items=all_reports,
        admin_emails=admin_emails,
        category=''  # not used for category-based filtering here
    )

@app.route('/claim/<int:report_id>')
def claim_report(report_id):
    if 'email' not in session:
        return redirect(url_for('do_login'))
    rpt = Report.query.get_or_404(report_id)
    if not rpt.claimed:
        rpt.claimed = True
        db.session.commit()
        flash('Report claimed successfully.')
    return redirect(request.referrer or url_for('show_home'))


@app.route('/reports')
@admin_only
def list_reports():
    reports = Report.query.order_by(Report.timestamp.desc()).all()
    return render_template('reports.html', reports=reports)


@app.route('/report/<int:report_id>/claim')
def claim_by_id(report_id):
    if 'email' not in session:
        return redirect(url_for('do_login'))

    rpt = Report.query.get_or_404(report_id)
    if not rpt.claimed:
        rpt.claimed = True
        db.session.commit()
        flash('You have claimed the item.')
    return redirect(request.referrer or url_for('show_home'))


@app.route('/help')
def help_page():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    return render_template('help.html')


@app.route('/settings')
def settings():
    if 'email' not in session:
        return redirect(url_for('do_login'))
    return render_template('settings.html')


# ───── NEW: add_comment stub ─────
@app.route('/add-comment/<int:report_id>', methods=['POST'], endpoint='add_comment')
def add_comment(report_id):
    flash(f"Received request to add a comment on report #{report_id}.")
    return redirect(url_for('show_home'))


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


# ───── Create DB & Seed Admin ─────
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='alice@somaiya.edu').first():
        pw_hash = generate_password_hash('apple123')
        alice_user = User(
            email='alice@somaiya.edu',
            password_hash=pw_hash,
            roles=''  # leave blank or set 'admin' if you want this user to be an admin
        )
        db.session.add(alice_user)
    db.session.commit()

if __name__ == '__main__':
    app.run()

