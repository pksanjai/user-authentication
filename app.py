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
otps_col = dp['otps']

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
        with smtplib.SMTP_SSL(SMTP_SERVER<SMTP_PORT) as sarver:
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
    return hash_otp(otp_input) == doc['otp_hash']

def remove_otp_docs(email: str,purpose: str):
    otps_col.delete_many({
        'email': email,
        'purpose': purpose
    })
    
