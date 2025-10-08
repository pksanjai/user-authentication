import os
import secrets
import hashlib
from datetime import datetime,timedelta

from flask import Flask, render_template, request, redirect, session, flash, url_for

from pymongo import MongoClient

from dotenv import load_dotenv

import bcrypt
import smtplib
from email.mime.text import MIMEText

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY',secrets.token_urlsafe(32))
MONGO_URI = os.getenv('MONGO_URI','mongodb://localhost:27017')
MONGO_DB = os.getenv('MONGO_DB', 'dark')

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT',465))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

OTP_TTL = int(os.getenv('OTP_TTL_SECONDS',400))

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users_col = db['users']
otps_col = db['otps']

otps_col.create_index('expires_at',expireAfterSeconds = 0)

def generate_otp():
    return f"{secrets.randbelow(10**6):06d}"

def hash_otp(otp: str) -> str:
    return hashlib.sha256((otp+app.config['SECRET_KEY']).encode()).hexdigest()

def send_email(recipient: str, subject: str, body:str):
    if not (SMTP_SERVER and SMTP_USERNAME and SMTP_PASSWORD):
        app.logger.error("SMTP configuration error.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = recipient
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        app.logger.error(f"SMTP authentication error: {e}")
        raise
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        raise
    
def create_and_send_otp(email:str, purpose:str):
    otp = generate_otp()
    otp_h = hash_otp(otp)
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=OTP_TTL)
    otps_col.insert_one({
        'email': email,
        'otp_h': otp_h,
        'purpose': purpose,
        'created_at': now,
        'expires_at': expires_at
    })
    subject = f"Your {purpose} OTP Code"
    body = f"Your OTP code is: {otp}. It will expire in {OTP_TTL//60} minutes."
    send_email(email,subject,body)
    
    return otp

def verify_otp_in_db(email:str,purpose: str, otp_input: str) -> bool:
    doc = otps_col.find_one({
        'email': email,
        'purpose': purpose
    })
    if not doc:
        return False
    if datetime.utcnow() > doc.get('expires_at',datetime.utcnow()):
        return False
    return hash_otp(otp_input) == doc['otp_h']

def remove_otp_docs(email: str,purpose: str):
    otps_col.delete_many({
        'email': email,
        'purpose': purpose
    })
    
# Route

@app.route('/')
def index():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Signup route
@app.route('/signup', methods = ['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip()
        password = request.form['password']
        if users_col.find_one({'email': email}):
            flash("Email already registered. Try login.",'warning')
            return redirect(url_for('signup'))
        
        password_hash = bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
        session['temp_user'] = {'email':email,'username':username,'password_hash':password_hash}
        
        try:
            create_and_send_otp(email,'signup')
        except Exception:
            flash('Failed to send OTP email. Check SMTP config.','danger')
            return redirect(url_for('signup'))
        
        
        flash('OTP sent to your mail. Enter it to complete signup.','info')
        return redirect(url_for('verify_signup_otp'))
    return render_template('signup.html')


@app.route('/verify-signup-otp', methods = ['GET','POST'])
def verify_signup_otp():
    temp = session.get('temp_user')
    if not temp:
        flash('NO signup in process.','warning')
        return redirect(url_for('signup'))
    email = temp['email']
    if request.method == 'POST':
        otp = request.form['otp'].strip()
        if verify_otp_in_db(email,'signup',otp):
            users_col.insert_one({
                'email' : email,
                'username' : temp['username'],
                'password': temp['password_hash'],
                'created_at' : datetime.utcnow()
                })
            remove_otp_docs(email,'signup')
            session.pop('temp_user',None)
            flash('Signup successful. Please login.','success')
            return redirect(url_for('login'))
        
        else:
            flash('Invalid or expired OTP.','danger')
            
    return render_template('verify_signup_otp.html',email = email,purpose='signup')


# Login with password
@app.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = users_col.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode(),user['password'].encode()):
            session['username'] = email
            flash('Login successful','success')
            return redirect(url_for('dashboard'))
        flash('Incorrect credentials','danger')
    return render_template('login.html')

# Login with Otp

@app.route('/login-otp',methods = ['GET','POST'])
def login_otp_request():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        if not users_col.find_one({'email': email}):
            flash('Email not registered.','warning')
            return redirect(url_for('login_otp_request'))
        try:
            create_and_send_otp(email,'login')
        except Exception:
            flash('Failed to send OTP email. Check SMTP config.','danger')
            return redirect(url_for('login_otp_request'))
        session['login_otp_email'] = email
        flash('OTP sent to your mail. Enter it to login.','info')
        return redirect(url_for('login_otp_verify'))
    return render_template('login_otp.html')

@app.route('/login-otp-verify',methods = ['GET','POST'])
def login_otp_verify():
    email = session.get('login_otp_email')
    if not email:
        flash('Strat login with OTP first.','warning')
        return redirect(url_for('login_otp_request'))
    if request.method == 'POST':
        otp = request.form['otp'].strip()
        if verify_otp_in_db(email,'login',otp):
            remove_otp_docs(email,'login')
            session.pop('login_otp_email',None)
            session['username'] = email
            flash('Login by otp successful','success')
            return redirect(url_for('dashboard'))
        flash('Invalid or expired OTP.','danger')
        # eeeeeeeee
    return render_template('verify_login_otp.html',email = email,purpose = 'Login')

# NO signup
# Forgot password -> send otp
@app.route('/forgot-password',methods = ['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        if not users_col.find_one({'email' : email}):
            flash("email not fount",'warning')
            return redirect(url_for('forgot_password'))
        try:
            create_and_send_otp(email,'reset')
        except Exception:
            flash('falied to send OTP','danger')
            return redirect(url_for('forgot_password'))
        session['reset_email'] = email
        flash('OTP send. Check your email.','info')
        return redirect(url_for('reset_password_verify'))
    return render_template('forgot_password.html')

@app.route('/reset-password-verify',methods = ['GET','POST'])
def reset_password_verify():
    email = session.get('reset_email')
    if not email:
        flash('Start password reset first.','warning')
        return redirect(url_for('forgot_password'))
    if request.method =='POST':
        otp = request.form['otp'].strip()
        if verify_otp_in_db(email,'reset',otp):
            remove_otp_docs(email,'reset')
            session.pop('reset_email',None)
            session['reset_allowed_for'] = email
            flash('OTP verified. Set new password.','info')
            return redirect(url_for('reset_password'))
        flash('Invalid or expired OTP.','danger')
    return render_template('reset_password_verify.html',email = email,purpose = 'Reset Password')

@app.route('/reset-password',methods = ['GET','POST'])
def reset_password():
    email = session.get('reset_allowed_for')
    if not email:
        flash('OTP verification required.','warning')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form['password']
        hashed = bcrypt.hashpw(new_password.encode(),bcrypt.gensalt()).decode()
        users_col.update_one(
            {'email' : email},
            { '$set' : {'password' : hashed }}
            )
        session.pop('reset_allowed_for',None)
        flash('Password reset successful. Please login.','success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    email = session.get('username')
    if not email:
        flash('Login required','warning')
        return redirect(url_for('login'))
    user = users_col.find_one({'email': email})
    return render_template('dashboard.html',user = user)


@app.route('/logout')
def logout():
    session.pop('username',None)
    flash('Logged out','info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
