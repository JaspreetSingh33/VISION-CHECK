from flask import Flask, render_template, redirect, url_for, session, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os, re, json
from zoneinfo import ZoneInfo

from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")


app = Flask(__name__)
app.secret_key = 'your_secret_key'

# ---------------- DATABASE SETUP ----------------
if not os.path.exists('instance'):
    os.makedirs('instance')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    reports = db.relationship('VisionReport', backref='user', lazy=True)
    color_reports = db.relationship('ColorReport', backref='user', lazy=True)

class VisionReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    eye = db.Column(db.String(10))   # "Left" or "Right"
    mar = db.Column(db.Float)
    per_level = db.Column(db.Text)   # JSON string for 11 values
    total_correct = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ColorReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    avg_reaction = db.Column(db.Float)
    verdict = db.Column(db.String(200))
    protan = db.Column(db.Integer)
    deutan = db.Column(db.Integer)
    tritan = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AMDReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    eye = db.Column(db.String(10))
    q1 = db.Column(db.String(50))
    q2 = db.Column(db.String(50))
    q3 = db.Column(db.String(50))
    classification = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- HELPERS ----------------
def valid_email(email):
    return re.match(r'^[A-Za-z0-9]+@gmail\.com$', email)

def valid_password(pw):
    return len(pw) >= 8

def classify_eye(mar, total_correct):
    if mar is None:
        return ("⚪ No Data", "Test not completed.", "neutral")
    if mar <= 0.05 and total_correct >= 50:
        return ("💚 Superior Vision", "Excellent clarity and focus across all levels.", "superior")
    if mar >= 0.4 and total_correct <= 25:
        return ("🔴 Weak Vision", "Significant difficulty with fine details. Clinic visit recommended.", "poor")
    if mar >= 0.25 and total_correct <= 35:
        return ("🟡 Mild Weakness", "Possible refractive error. Consider corrective lenses soon.", "moderate")
    if mar >= 0.1 and total_correct <= 45:
        return ("🟢 Normal Vision", "Healthy visual acuity. Maintain regular eye check-ups.", "good")
    return ("💚 Superior Vision", "Excellent clarity and precision.", "superior")

def classify_amd(q1, q2, q3):
    abnormal = (q1 == "Darker areas") or (q2 == "Distorted") or (q3 == "Missing lines")
    if not abnormal:
        return "Normal macular function"
    elif (q3 == "Missing lines") or (q2 == "Distorted"):
        return "Potential AMD signs"
    elif q1 == "Darker areas":
        return "Mild irregularity detected"
    return "Normal macular function"

def to_ist(dt):
    if not dt:
        return ""
    # If timestamp is naive (no timezone), assume it is UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(IST).strftime('%Y-%m-%d %H:%M')


# ---------------- AUTH ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        user = User.query.filter_by(email=email).first()
        if not user or user.password != password:
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
        session['user_id'] = user.id
        session['user_name'] = user.name
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email_raw = request.form['email'].strip()          # original email
        email_check = email_raw.lower()                    # convert only for checking
        password = request.form['password'].strip()

        # Case-insensitive check
        existing = User.query.filter(
            db.func.lower(User.email) == email_check
        ).first()

        if existing:
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))

        # Save original casing of email into DB
        new_user = User(name=name, email=email_raw, password=password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['user_name'] = new_user.name
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', name=session['user_name'])

# ---------------- TUMBLING E ----------------
@app.route('/tumbling_e/start')
def tumbling_e_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tumbling_start.html', which_eye='Left')

@app.route('/tumbling_e/test')
def tumbling_e_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tumbling_test.html', which_eye='Left')

@app.route('/tumbling_e_right/start')
def tumbling_e_right_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tumbling_right_start.html', which_eye='Right')

@app.route('/tumbling_e_right/test')
def tumbling_e_right_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tumbling_test.html', which_eye='Right')

@app.route('/save_results', methods=['POST'])
def save_results():
    if 'user_id' not in session:
        return {'ok': False, 'error': 'Not logged in'}

    data = request.json or {}
    eye = data.get('eye')
    mar = data.get('mar')
    per_level = data.get('per_level') or [0]*11
    total_correct = sum(per_level)

    if eye not in ('Left', 'Right'):
        return {'ok': False, 'error': 'Invalid eye data'}

    report = VisionReport(
        user_id=session['user_id'],
        eye=eye,
        mar=mar,
        per_level=json.dumps(per_level),
        total_correct=total_correct
    )
    db.session.add(report)
    db.session.commit()
    return {'ok': True}

# ✅ FIXED ONLY THIS: Tumbling E report now reads latest from DB (not session), keeps template shape
@app.route('/tumbling_e/report')
def tumbling_e_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch a handful of latest records and pick most recent Left/Right
    reports = (VisionReport.query
               .filter_by(user_id=session['user_id'])
               .order_by(VisionReport.created_at.desc())
               .limit(10).all())

    left_data = next((r for r in reports if r.eye == 'Left'), None)
    right_data = next((r for r in reports if r.eye == 'Right'), None)

    def safe_parse(rep):
        if not rep:
            return {'mar': None, 'per_level': [0]*11, 'total_correct': 0, 'verdict': ("⚪ No Data", "Test not taken", "neutral")}
        try:
            per_level = json.loads(rep.per_level or '[]')
        except Exception:
            per_level = [0]*11
        verdict = classify_eye(rep.mar, rep.total_correct)
        return {'mar': rep.mar, 'per_level': per_level, 'total_correct': rep.total_correct, 'verdict': verdict}

    left = safe_parse(left_data)
    right = safe_parse(right_data)

    return render_template(
        'tumbling_report.html',
        name=session.get('user_name', 'User'),
        left=left,
        right=right,
        left_verdict=left['verdict'],
        right_verdict=right['verdict']
    )

# ---------------- COLOR BLINDNESS (unchanged) ----------------
@app.route('/colorblind_start')
def colorblind_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('colorblind_start.html')

@app.route('/colorblind_left_start')
def colorblind_left_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('colorblind_left_start.html')

@app.route('/colorblind_right_start')
def colorblind_right_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('colorblind_right_start.html')

@app.route('/colorblind_test')
def colorblind_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('colorblind_test.html')

@app.route('/colorblind_report')
def colorblind_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('colorblind_report.html')

@app.route('/save_colorblind_results', methods=['POST'])
def save_colorblind_results():
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'Not logged in'})

    data = request.json or {}
    try:
        new_report = ColorReport(
            user_id=session['user_id'],
            score=int(data.get('score', 0)),
            total=int(data.get('total', 10)),
            avg_reaction=float(data.get('avg_reaction', 0.0)),
            verdict=(data.get('verdict') or '').strip(),
            protan=int(data.get('protan', 0)),
            deutan=int(data.get('deutan', 0)),
            tritan=int(data.get('tritan', 0))
        )
        db.session.add(new_report)
        db.session.commit()
        return jsonify({'ok': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 400

# ---------------- AMD (unchanged) ----------------
@app.route('/amd/start')
def amd_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('amd_start.html')

@app.route('/amd/left_cover')
def amd_left_cover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('amd_left_cover.html')

@app.route('/amd/right_cover')
def amd_right_cover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('amd_right_cover.html')

@app.route('/amd/test')
def amd_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    eye = request.args.get('eye', 'Right')
    return render_template('amd_test.html', eye=eye)

@app.route('/amd/save', methods=['POST'])
def amd_save():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    eye = request.form.get('eye', 'Right')
    q1 = request.form.get('q1', 'Normal')
    q2 = request.form.get('q2', 'Normal')
    q3 = request.form.get('q3', 'All lines visible')
    verdict = classify_amd(q1, q2, q3)

    data = {'q1': q1, 'q2': q2, 'q3': q3, 'classification': verdict}
    if eye == 'Right':
        session['amd_right'] = data
        return redirect(url_for('amd_right_cover'))
    else:
        session['amd_left'] = data
        right = session.get('amd_right')
        left = data
        db.session.add_all([
            AMDReport(user_id=session['user_id'], eye='Right', **(right or {})),
            AMDReport(user_id=session['user_id'], eye='Left', **left)
        ])
        db.session.commit()
        return redirect(url_for('amd_report'))

@app.route('/amd/report')
def amd_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    left = session.get('amd_left') or {'q1':'Normal','q2':'Normal','q3':'All lines visible','classification':'Normal macular function'}
    right = session.get('amd_right') or {'q1':'Normal','q2':'Normal','q3':'All lines visible','classification':'Normal macular function'}

    left_view = {**left,'verdict':left.get('classification')}
    right_view = {**right,'verdict':right.get('classification')}

    def is_abnormal(b): 
        return not any(k in (b.get('verdict') or '').lower() for k in ['normal'])

    abnormal_left, abnormal_right = is_abnormal(left_view), is_abnormal(right_view)

    if not (abnormal_left or abnormal_right):
        summary="Both eyes show normal macular function."
        condition="Normal Retina Function";severity="Normal"
        recommendation="Routine eye check every 12 months."
        advice="Maintain leafy-green diet and reduce screen strain."
    elif (abnormal_left and not abnormal_right) or (abnormal_right and not abnormal_left):
        summary="Minor irregularity detected in one eye."
        condition="Early Macular Change";severity="Mild"
        recommendation="Book an eye exam within 2–4 weeks."
        advice="Keep good lighting and monitor vision changes."
    elif abnormal_left and abnormal_right:
        if ("Missing lines" in [left_view['q3'], right_view['q3']]) or ("Distorted" in [left_view['q2'], right_view['q2']]):
            summary="Significant distortion in both eyes — possible AMD."
            condition="Advanced AMD (Suspected)";severity="Severe"
            recommendation="Seek immediate evaluation by a specialist."
            advice="Track any sudden vision change and maintain good lighting."
        else:
            summary="Moderate distortion patterns in both eyes."
            condition="Intermediate AMD";severity="Moderate"
            recommendation="Consult ophthalmologist soon."
            advice="Maintain eye-healthy diet and 40–50 cm screen distance."
    else:
        summary="Inconclusive results."
        condition="Undetermined";severity="Unclear"
        recommendation="Repeat AMD test or consult a professional."
        advice="Ensure proper lighting during testing."

    return render_template('amd_report.html',
        left=left_view, right=right_view,
        summary_text=summary, condition=condition,
        severity=severity, recommendation=recommendation, advice=advice)




    # ---------------- ASTIGMATISM ----------------

class AstigmatismReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    eye = db.Column(db.String(10))  # "Left" or "Right"
    q1 = db.Column(db.String(50))
    q2 = db.Column(db.String(50))
    q3 = db.Column(db.String(50))
    q4 = db.Column(db.String(50))
    classification = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def classify_astigmatism(q1, q2, q3, q4):
    """Classify based on responses for distorted or lighter/darker lines."""
    answers = [q1, q2, q3, q4]

    # count how many answers show irregularity
    score = sum(
        1 for a in answers if a and (
            "distorted" in a.lower() or
            "blurred" in a.lower() or
            "lighter" in a.lower() or
            "darker" in a.lower()
        )
    )

    # simple scoring logic
    if score == 0:
        return "Normal vision (No signs of astigmatism)"
    elif score <= 2:
        return "Mild irregularity — possible minor astigmatism"
    else:
        return "Likely astigmatism — professional evaluation recommended"

@app.route('/astigmatism/start')
def astigmatism_start():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('astigmatism_intro.html')

@app.route('/astigmatism/left')
def astigmatism_left_cover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('astigmatism_left.html')

@app.route('/astigmatism/left/q<int:n>', methods=['GET','POST'])
def astigmatism_left_q(n):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        ans = request.form.get('answer')
        session.setdefault('astig_left', {})
        session['astig_left'][f'q{n}'] = ans
        session.modified = True

        if n < 4:
            return redirect(url_for('astigmatism_left_q', n=n+1))
        else:
            return redirect(url_for('astigmatism_right_cover'))
    return render_template(f'astigmatism_left_q{n}.html')

@app.route('/astigmatism/right')
def astigmatism_right_cover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('astigmatism_right.html')

@app.route('/astigmatism/right/q<int:n>', methods=['GET','POST'])
def astigmatism_right_q(n):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        ans = request.form.get('answer')
        session.setdefault('astig_right', {})
        session['astig_right'][f'q{n}'] = ans
        session.modified = True

        if n < 4:
            return redirect(url_for('astigmatism_right_q', n=n+1))
        else:
            return redirect(url_for('astigmatism_report'))
    return render_template(f'astigmatism_right_q{n}.html')

@app.route('/astigmatism/report')
def astigmatism_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    left = session.get('astig_left', {})
    right = session.get('astig_right', {})

    left_result = classify_astigmatism(
        left.get('q1'), left.get('q2'), left.get('q3'), left.get('q4'))
    right_result = classify_astigmatism(
        right.get('q1'), right.get('q2'), right.get('q3'), right.get('q4'))

    # Save both eyes to DB
    db.session.add_all([
        AstigmatismReport(
            user_id=session['user_id'], eye='Left', **left, classification=left_result),
        AstigmatismReport(
            user_id=session['user_id'], eye='Right', **right, classification=right_result)
    ])
    db.session.commit()

    return render_template('astigmatism_report.html',
                           left=left, right=right,
                           left_result=left_result,
                           right_result=right_result)



# ---------------- VIEW ALL REPORTS (unchanged formatting) ----------------
@app.route('/reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Tumbling E grouped pairs (10 min window)
    reports = VisionReport.query.filter_by(user_id=session['user_id']).order_by(VisionReport.created_at.desc()).all()
    grouped, used = [], set()
    for i, r in enumerate(reports):
        if i in used: continue
        pair={'time':r.created_at,'left':None,'right':None}
        if r.eye=='Left': pair['left']=r
        elif r.eye=='Right': pair['right']=r
        for j, r2 in enumerate(reports):
            if i==j or j in used: continue
            if abs((r.created_at - r2.created_at).total_seconds()) < 600:
                if r2.eye=='Left' and not pair['left']: pair['left']=r2; used.add(j)
                elif r2.eye=='Right' and not pair['right']: pair['right']=r2; used.add(j)
        used.add(i); grouped.append(pair)

    formatted=[]
    for g in grouped:
        def safe_parse(rep):
            if not rep:
                return {'mar':None,'total_correct':0,'verdict':("⚪ No Data","Test not taken","neutral")}
            verdict = classify_eye(rep.mar, rep.total_correct)
            return {'mar':rep.mar or 0,'total_correct':rep.total_correct or 0,'verdict':verdict}
        formatted.append({
            'time': to_ist(g['time']),
            'left': safe_parse(g['left']),
            'right': safe_parse(g['right'])
        })

    # Color Blindness list
    color_qs = ColorReport.query.filter_by(user_id=session['user_id']).order_by(ColorReport.created_at.desc()).all()
    color_reports = [{
        'time': to_ist(c.created_at),
        'score': c.score, 'total': c.total,
        'avg_reaction': round(c.avg_reaction or 0, 1),
        'verdict': c.verdict,
        'protan': c.protan, 'deutan': c.deutan, 'tritan': c.tritan
    } for c in color_qs]

    # AMD list
    amd_qs = AMDReport.query.filter_by(user_id=session['user_id']).order_by(AMDReport.created_at.desc()).all()
    amd_reports = [{
        'time': to_ist(a.created_at),
        'eye': a.eye,
        'q1': a.q1, 'q2': a.q2, 'q3': a.q3,
        'classification': a.classification
    } for a in amd_qs]

    



    # ✅ Astigmatism list — NEW
    astig_qs = (AstigmatismReport.query
                .filter_by(user_id=session['user_id'])
                .order_by(AstigmatismReport.created_at.desc())
                .all())
    astig_reports = [{
        'time': to_ist(a.created_at),
        'eye': a.eye,
        'q1': a.q1, 'q2': a.q2, 'q3': a.q3, 'q4': a.q4,
        'classification': a.classification
    } for a in astig_qs]

    # Render template with all report types
    return render_template('reports.html',
        grouped_reports=formatted,
        color_reports=color_reports,
        amd_reports=amd_reports,
        astig_reports=astig_reports,   # <— added here
        name=session.get('user_name', 'User'))

@app.route('/nearby_clinics', methods=['POST'])
def nearby_clinics():
    data = request.json
    lat = data.get("lat")
    lon = data.get("lon")

    # Real Eye Clinics in Patiala
    clinics = [
        {
            "name": "Amar Hospital – Eye Department",
            "address": "Income Tax Office Road, Bank Colony, Patiala",
            "distance": 1.2,
            "map_url": "https://maps.google.com/?q=Amar+Hospital+Patiala"
        },
        {
            "name": "Garg Eye Hospital (NABH Accredited)",
            "address": "Sirhind Road, Patiala",
            "distance": 2.5,
            "map_url": "https://maps.google.com/?q=Garg+Eye+Hospital+Patiala"
        },
        {
            "name": "Bansal Eye Hospital & Laser Centre",
            "address": "41, Bank Colony, Khalsa College Road, Patiala",
            "distance": 1.8,
            "map_url": "https://maps.google.com/?q=Bansal+Eye+Hospital+Patiala"
        },
        {
            "name": "Dr. G.S. Randhawa Eye Hospital (LJ Eye Institute)",
            "address": "Fateh Colony, Sanauri Adda Road, Patiala",
            "distance": 3.0,
            "map_url": "https://maps.google.com/?q=Randhawa+Eye+Hospital+Patiala"
        },
        {
            "name": "NETRA PRAKASH EYE CENTRE",
            "address": "Urban Estate Phase-2, Patiala",
            "distance": 3.4,
            "map_url": "https://maps.google.com/?q=Navdeep+Eye+Centre+Patiala"
        },
        {
            "name": "Lenskart – Leela Bhawan",
            "address": "SCO 79, Ground Floor, Leela Bhawan, Patiala",
            "distance": 1.0,
            "map_url": "https://maps.google.com/?q=Lenskart+Leela+Bhawan+Patiala"
        },
        {
            "name": "Dr. K.P. Singh Eye Clinic",
            "address": "22 No. Phatak Road, Patiala",
            "distance": 1.3,
            "map_url": "https://maps.google.com/?q=KP+Singh+Eye+Clinic+Patiala"
        },
    ]

    # Sort by nearest distance
    clinics_sorted = sorted(clinics, key=lambda x: x["distance"])

    return jsonify({"clinics": clinics_sorted})


# ---------------- RUN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

