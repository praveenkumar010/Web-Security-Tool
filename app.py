from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from scanner import scan_website
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'cybersecurityproject'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# DATABASE

db = SQLAlchemy(app)

# LOGIN MANAGER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# =========================================
# DATABASE MODELS
# =========================================

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class ScanHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))

# =========================================
# USER LOADER
# =========================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =========================================
# LOGIN
# =========================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(
            username=username,
            password=password
        ).first()

        if user:
            login_user(user)
            return redirect(url_for('home'))

    return render_template('login.html')

# =========================================
# LOGOUT
# =========================================

@app.route('/logout')
@login_required
def logout():

    logout_user()

    return redirect(url_for('login'))

# =========================================
# HOME
# =========================================

@app.route('/')
@login_required
def home():
    return render_template('index.html')

# =========================================
# SCAN API
# =========================================

@app.route('/scan', methods=['POST'])
@login_required
def scan():

    data = request.get_json()

    url = data.get('url')

    results = scan_website(url)

    if 'error' not in results:

        scan_data = ScanHistory(
            url=results['url'],
            risk_score=results['risk_score'],
            risk_level=results['risk_level']
        )

        db.session.add(scan_data)
        db.session.commit()

    return jsonify(results)

# =========================================
# HISTORY
# =========================================

@app.route('/history')
@login_required
def history():

    scans = ScanHistory.query.all()

    history_data = []

    for scan in scans:

        history_data.append({
            'url': scan.url,
            'risk_score': scan.risk_score,
            'risk_level': scan.risk_level
        })

    return jsonify(history_data)

# =========================================
# PDF REPORT
# =========================================

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():

    data = request.get_json()

    os.makedirs('reports', exist_ok=True)

    pdf_path = 'reports/security_report.pdf'

    doc = SimpleDocTemplate(pdf_path)

    styles = getSampleStyleSheet()

    content = []

    title = Paragraph(
        'Cyber Security Scan Report',
        styles['Title']
    )

    content.append(title)

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"URL: {data['url']}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {data['risk_score']}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Risk Level: {data['risk_level']}",
            styles['BodyText']
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            'Detected Vulnerabilities',
            styles['Heading2']
        )
    )

    for vuln in data['vulnerabilities']:

        content.append(

            Paragraph(
                f"{vuln['type']} - {vuln['severity']}<br/>{vuln['description']}",
                styles['BodyText']
            )

        )

        content.append(Spacer(1, 10))

    doc.build(content)

    return send_file(pdf_path, as_attachment=True)

# =========================================
# MAIN
# =========================================

if __name__ == '__main__':

    with app.app_context():

        db.create_all()

        if not User.query.filter_by(username='admin').first():

            user = User(
                username='admin',
                password='admin123'
            )

            db.session.add(user)
            db.session.commit()

    app.run(debug=True)