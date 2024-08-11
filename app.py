import logging
import sys
import oauthlib
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify, flash, send_file
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import time
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import requests
import pyotp
import qrcode
from io import BytesIO
import base64
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import random
import modules.streaming
import cv2
from datetime import datetime, timedelta, timezone
from twilio.rest import Client
from oauthlib.oauth2 import WebApplicationClient
import json
import MySQLdb.cursors
from qrcode.image.pil import PilImage
from PIL import Image
from cryptography.fernet import Fernet
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'pdf', 'docx'}
VIRUSTOTAL_API_KEY = '27ac8bc4416b703a61164f18929555fb7260940e16623b729792da460407acf7'

# Secret key for session management
app.secret_key = os.urandom(24)

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'secprj'

mysql = MySQL(app)

UPLOAD_FOLDER = 'uploads/'
TEMP_FOLDER = 'temp_uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_FOLDER'] = TEMP_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

FACE_IMAGES_FOLDER = 'static/face_images'
app.config['FACE_IMAGES_FOLDER'] = FACE_IMAGES_FOLDER
os.makedirs(FACE_IMAGES_FOLDER, exist_ok=True)


# Ensure the uploads folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)

# hCaptcha configurations
HCAPTCHA_SECRET_KEY = 'ES_c3d38c11ba6842b3bbc84a16f8d378f5'

# Email settings
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'myuploadsapplication@gmail.com'
SMTP_PASSWORD = 'kfaomwsmwyalaifg'

# OAuth 2 client setup
GOOGLE_CLIENT_ID = '296943099353-lo8us1ap7kf109a3kam4ss65e886etd6.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

with open('encryption_key.key', 'rb') as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

def encrypt_path(file_path):
    """Encrypts the file path using Fernet symmetric encryption."""
    encrypted_path = cipher.encrypt(file_path.encode())
    return encrypted_path.decode()

def decrypt_path(encrypted_path):
    """Decrypts the encrypted file path."""
    decrypted_path = cipher.decrypt(encrypted_path.encode())
    return decrypted_path.decode()

def log_user_action(user_id, session_id, action):
    log_file_path = 'user_actions.log'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f'{timestamp} - Username: {user_id} - Session ID: {session_id} - Action: {action}\n'

    with open(log_file_path, 'a') as log_file:
        log_file.write(log_entry)


@app.route('/lock_session', methods=['POST'])
def lock_session():
    if 'loggedin' in session:
        session['locked'] = True
        log_user_action(session['username'], session['session_id'], 'Locked session')
        if session.get('role') == 'admin':
            return redirect(url_for('admin_unlock_session'))
        else:
            return redirect(url_for('unlock_session'))

@app.route('/unlock_session', methods=['GET', 'POST'])
def unlock_session():
    msg = ''
    if 'locked' not in session or 'id' not in session:
        return redirect(url_for('home'))

    # Initialize or increment the failed attempts count
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    if request.method == 'POST':
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            session.pop('locked', None)
            session.pop('failed_attempts', None)  # Reset failed attempts
            log_user_action(session['username'], session['session_id'], 'Unlocked session')
            return redirect(url_for('home'))
        else:
            session['failed_attempts'] += 1
            if session['failed_attempts'] >= 5:
                log_user_action(session['username'], session['session_id'], 'Too many failed unlock attempts')
                session.clear()  # Clear the session
                msg = 'Too many failed attempts. Redirecting to login.'
                return redirect(url_for('login'))  # Redirect to login
            else:
                msg = 'Incorrect password! Please try again.'

    return render_template('unlock_session.html',msg=msg)


@app.before_request
def before_request():
    if 'loggedin' in session:
        if 'locked' in session:
            if session.get('role') == 'admin':
                if request.endpoint not in ['admin_unlock_session', 'static']:
                    return redirect(url_for('admin_unlock_session'))
            else:
                if request.endpoint not in ['unlock_session', 'static']:
                    return redirect(url_for('unlock_session'))

        if 'session_id' not in session:
            session['session_id'] = hashlib.sha256(os.urandom(64)).hexdigest()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_session_logs WHERE username = %s AND session_id = %s',
                       (session['username'], session['session_id']))
        account = cursor.fetchone()

        if account and account['session_id'] != session['session_id']:
            session.clear()
            return redirect(url_for('login'))

        log_user_action(session['username'], session['session_id'], f'Accessed {request.endpoint}')




def generate_otp_code():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp_code):
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your OTP Code"
    message["From"] = SMTP_USERNAME
    message["To"] = email

    text = f"Your OTP code is: {otp_code}\n\nThis code will expire in 5 minutes."
    html = f"""
    <html>
    <body>
        <h2>Your OTP Code</h2>
        <p>Your OTP code is: <strong>{otp_code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, message.as_string())

def send_otp_sms(phone_number, otp_code):
    message = f"Your OTP code is: {otp_code}\n\nThis code will expire in 5 minutes."
    send_sms(phone_number, message)

def generate_and_send_sms_2fa_code(user_id, phone_number):
    code = generate_sms_2fa_code()
    expiration = datetime.utcnow() + timedelta(minutes=5)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE users SET sms_2fa_code = %s, sms_2fa_expiration = %s WHERE id = %s', (code, expiration, user_id))
    mysql.connection.commit()
    send_sms_2fa_code(phone_number, code)

def generate_sms_2fa_code():
    return str(random.randint(100000, 999999))

def send_sms_2fa_code(phone_number, code):
    message = f"Your 2FA code is: {code}\n\nThis code will expire in 5 minutes."
    send_sms(phone_number, message)

def generate_and_send_sms_2fa_code(user_id, phone_number):
    code = generate_sms_2fa_code()
    expiration = datetime.utcnow() + timedelta(minutes=5)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE users SET sms_2fa_code = %s, sms_2fa_expiration = %s WHERE id = %s', (code, expiration, user_id))
    mysql.connection.commit()
    send_sms_2fa_code(phone_number, code)

def send_sms(phone_number, message):
    account_sid = 'AC3f094a4379c84b122ef44477e485d7aa'
    auth_token = '2f4a8be54660d5126d7ee09308435ddc'
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=message,
        from_='+13305945838',  # Your Twilio number
        to=phone_number
    )

def is_valid_phone_number(phone_number):
    # Basic validation to check if the phone number starts with + and is followed by digits
    return re.match(r'^\+\d{10,15}$', phone_number) is not None

def generate_phone_verification_code():
    return str(random.randint(100000, 999999))

def send_phone_verification_code(phone_number):
    code = generate_phone_verification_code()
    message = f"Your phone verification code is: {code}"
    send_sms(phone_number, message)
    return code

def generate_2fa_code():
    return str(random.randint(100000, 999999))

def send_2fa_email(email, code):
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your 2FA Code"
    message["From"] = SMTP_USERNAME
    message["To"] = email

    text = f"Your 2FA code is: {code}\n\nThis code will expire in 5 minutes."

    html = f"""
    <html>
    <body>
        <h2>Your 2FA Code</h2>
        <p>Your 2FA code is: <strong>{code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
        <p>Please enter this code to complete your login.</p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, message.as_string())

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        data = response.json()
        return data['ip']
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return None

def generate_mfa_secret():
    return pyotp.random_base32()

def send_verification_email(email, token):
    message = MIMEMultipart("alternative")
    message["Subject"] = "Account Verification"
    message["From"] = SMTP_USERNAME
    message["To"] = email

    text = f"Please click the link to verify your account: {url_for('verify_email', token=token, _external=True)}"
    part = MIMEText(text, "plain")
    message.attach(part)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, message.as_string())

def send_login_alert(email, ip):
    location_data = get_location_from_ip(ip)

    city = location_data.get('city', 'Unknown')
    region = location_data.get('region', 'Unknown')
    country = location_data.get('country', 'Unknown')
    loc = location_data.get('loc', 'Unknown')
    org = location_data.get('org', 'Unknown')
    timezone = location_data.get('timezone', 'Unknown')

    message = MIMEMultipart("alternative")
    message["Subject"] = "New Sign-in Alert"
    message["From"] = SMTP_USERNAME
    message["To"] = email

    text = f"A new sign-in to your account was detected from IP: {ip}. If this was not you, please secure your account."

    html = f"""
    <html>
    <body>
        <h2>New Sign-in Alert</h2>
        <p>A new sign-in to your account was detected. If this was not you, please secure your account immediately.</p>
        <h3>Sign-in Details:</h3>
        <ul>
            <li><strong>IP Address:</strong> {ip}</li>
            <li><strong>Location:</strong> {city}, {region}, {country}</li>
            <li><strong>Coordinates:</strong> {loc}</li>
            <li><strong>ISP:</strong> {org}</li>
            <li><strong>Timezone:</strong> {timezone}</li>
        </ul>
        <p>If you did not sign in from this location, please change your password immediately and contact support.</p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, message.as_string())

def get_device_hash():
    device_info = request.headers.get('User-Agent', '') + request.remote_addr
    return hashlib.sha256(device_info.encode()).hexdigest()

def detect_face(image_path):
    # Load the cascade
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    # Read the input image
    img = cv2.imread(image_path)
    if img is None:
        return False

    # Convert into grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Detect faces
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    # If no faces are detected, return False
    if len(faces) == 0:
        return False

    # Faces found
    return True

@app.route('/')
def firstpage():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'confirm_password' in request.form:
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        hcaptcha_response = request.form.get('h-captcha-response')
        if not hcaptcha_response or not validate_hcaptcha(hcaptcha_response):
            msg = 'Captcha validation failed!'
            return render_template('register.html', msg=msg)

        password_requirements = (
            len(password) >= 8,
            re.search(r'[A-Z]', password),
            re.search(r'[a-z]', password),
            re.search(r'[0-9]', password),
            re.search(r'[\W_]', password)
        )

        if not all(password_requirements):
            msg = 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
            return render_template('register.html', msg=msg)

        if password != confirm_password:
            msg = 'Passwords do not match!'
            return render_template('register.html', msg=msg)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        email_account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif email_account:
            msg = 'Email already registered!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            verification_token = generate_mfa_secret()
            cursor.execute(
                'INSERT INTO users (username, password, email, verification_token, email_verified) VALUES (%s, %s, %s, %s, %s)',
                (username, hashed_password, email, verification_token, False))
            mysql.connection.commit()
            send_verification_email(email, verification_token)
            msg = 'You have successfully registered! Please check your email to verify your account.'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/verify/<token>')
def verify_email(token):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE verification_token = %s', (token,))
    account = cursor.fetchone()

    if account:
        cursor.execute('UPDATE users SET email_verified = %s, verification_token = NULL WHERE id = %s', (True, account['id']))
        mysql.connection.commit()
        msg = 'Your account has been verified! You can now log in.'
    else:
        msg = 'Verification failed! Invalid token.'

    return render_template('verify.html', msg=msg)

def validate_hcaptcha(response):
    payload = {
        'response': response,
        'secret': HCAPTCHA_SECRET_KEY
    }
    r = requests.post('https://hcaptcha.com/siteverify', data=payload)
    result = r.json()
    return result.get('success', False)

@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    if 'username' not in session or 'mfa_secret' not in session:
        return redirect(url_for('login'))

    username = session['username']
    mfa_secret = session['mfa_secret']
    otp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name="MyUploads")

    if request.method == 'POST':
        code = request.form.get('mfa_code')
        if pyotp.TOTP(mfa_secret).verify(code):
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE users SET mfa_secret = %s, mfa_enabled = %s, mfa_method = %s WHERE username = %s', (mfa_secret, True, 'app', username))
            mysql.connection.commit()
            session.clear()
            flash('MFA setup successful. Please log in again.')
            return redirect(url_for('mfa_success', mfa_method='app'))
        else:
            flash('Invalid MFA code. Please try again.')

    # Generate the QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=PilImage)

    # Save the image to a BytesIO object
    buffer = BytesIO()
    img.save(buffer, "PNG")
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template('setup_mfa.html', img_base64=img_base64)

@app.route('/mfa_success')
def mfa_success():
    mfa_method = request.args.get('mfa_method', 'none')
    return render_template('mfa_success.html', mfa_method=mfa_method)

def get_location_from_ip(ip):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        data = response.json()
        return data
    except Exception as e:
        print(f"Error getting location from IP: {e}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    # Initialize or increment the failed attempts count
    if 'user_failed_attempts' not in session:
        session['user_failed_attempts'] = 0

    if session['user_failed_attempts'] >= 5:
        print("Too many failed attempts. Terminating the program.")
        sys.exit("Program terminated due to too many failed login attempts.")

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username'].strip()
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            if account['role'] != 'user':
                msg = 'Unauthorized access for this role. Please use the admin login page.'
            elif not account['email_verified']:
                msg = 'Your account is not verified. Please check your email.'
            else:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['role'] = account['role']
                session['mfa_enabled'] = account['mfa_enabled']
                session['mfa_method'] = account['mfa_method']
                session['session_id'] = hashlib.sha256(os.urandom(64)).hexdigest()
                session['regenerate_time'] = datetime.now()

                session.pop('user_failed_attempts', None)  # Reset failed attempts
                log_user_action(session['username'], session['session_id'], 'Logged in')

                if account['mfa_enabled']:
                    if account['mfa_method'] == 'app':
                        session['mfa_secret'] = account['mfa_secret']
                        return redirect(url_for('mfa_verify'))
                    elif account['mfa_method'] == 'email':
                        code = generate_2fa_code()
                        expiration = datetime.now() + timedelta(minutes=5)
                        cursor.execute('UPDATE users SET email_2fa_code = %s, email_2fa_expiration = %s WHERE id = %s',
                                       (code, expiration, account['id']))
                        mysql.connection.commit()
                        send_2fa_email(account['email'], code)
                        return redirect(url_for('mfa_verify_email'))
                    elif account['mfa_method'] == 'sms' and account['phone_verified']:
                        generate_and_send_sms_2fa_code(account['id'], account['phone_number'])
                        return redirect(url_for('mfa_verify_sms'))
                else:
                    device_hash = get_device_hash()
                    cursor.execute('SELECT * FROM devices WHERE user_id = %s AND device_hash = %s',
                                   (account['id'], device_hash))
                    device = cursor.fetchone()

                    if not device:
                        user_ip = get_public_ip()
                        send_login_alert(account['email'], user_ip)
                        cursor.execute('INSERT INTO devices (user_id, device_hash) VALUES (%s, %s)',
                                       (account['id'], device_hash))
                        mysql.connection.commit()
                    return redirect(url_for('home'))
        else:
            session['user_failed_attempts'] += 1
            if session['user_failed_attempts'] >= 5:
                print("Too many failed attempts. Terminating the program.")
                sys.exit("Program terminated due to too many failed login attempts.")
            else:
                msg = 'Incorrect username/password!'

    return render_template('login.html', msg=msg)
@app.route('/face_login', methods=['POST'])
def face_login():
    msg = ''
    if request.method == 'POST':
        try:
            result = modules.streaming.analysis(
                db_path='static/face_images',
                model_name='VGG-Face',
                detector_backend='opencv',
                distance_metric='cosine',
                enable_face_analysis=False,
                source=0,  # This should be the index of the camera
                time_threshold=2,
                frame_threshold=5,
                anti_spoofing=True
            )
            if result['status'] == 'success' and result['verified']:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM users WHERE face_image = %s', (result['target_label'],))
                account = cursor.fetchone()
                if account:
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    log_action(account['username'], 'Logged in with face recognition')
                    if account['mfa_enabled']:
                        if account['mfa_method'] == 'app':
                            session['mfa_secret'] = account['mfa_secret']
                            return redirect(url_for('mfa_verify'))
                        elif account['mfa_method'] == 'email':
                            code = generate_2fa_code()
                            expiration = datetime.now() + timedelta(minutes=5)
                            cursor.execute('UPDATE users SET email_2fa_code = %s, email_2fa_expiration = %s WHERE id = %s',
                                           (code, expiration, account['id']))
                            mysql.connection.commit()
                            send_2fa_email(account['email'], code)
                            return redirect(url_for('mfa_verify_email'))
                        elif account['mfa_method'] == 'sms' and account['phone_verified']:
                            generate_and_send_sms_2fa_code(account['id'], account['phone_number'])
                            return redirect(url_for('mfa_verify_sms'))
                    else:
                        return redirect(url_for('home'))
                else:
                    msg = 'Face recognition failed! Account not found.'
            else:
                msg = 'Face recognition failed/spoof!'
        except Exception as e:
            print(f"Exception during face recognition: {e}")
            msg = 'An error occurred during face recognition.'
        return render_template('login.html', msg=msg)

    return render_template('login.html', msg="Face recognition not attempted")

@app.route('/mfa_verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'loggedin' not in session or 'mfa_secret' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('mfa_code')
        if pyotp.TOTP(session['mfa_secret']).verify(code):
            session.pop('mfa_secret', None)
            session['mfa_verified'] = True
            return redirect(url_for('home'))
        else:
            flash('Invalid MFA code. Please try again.')

    return render_template('mfa_verify.html')

@app.route('/mfa_verify_email', methods=['GET', 'POST'])
def mfa_verify_email():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT email, email_2fa_code, email_2fa_expiration FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()
    if not account:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'resend' in request.form:
            code = generate_2fa_code()
            expiration = datetime.now() + timedelta(minutes=5)
            cursor.execute('UPDATE users SET email_2fa_code = %s, email_2fa_expiration = %s WHERE id = %s', (code, expiration, session['id']))
            mysql.connection.commit()
            send_2fa_email(account['email'], code)
            flash('A new 2FA code has been sent to your email.')
            return redirect(url_for('mfa_verify_email'))

        code = request.form.get('mfa_code')
        if account['email_2fa_code'] == code and account['email_2fa_expiration'] > datetime.now():
            cursor.execute('UPDATE users SET email_2fa_code = NULL, email_2fa_expiration = NULL WHERE id = %s', (session['id'],))
            mysql.connection.commit()
            session['mfa_verified'] = True
            return redirect(url_for('home'))
        else:
            flash('Invalid or expired 2FA code. Please try again.')

    return render_template('mfa_verify_email.html', expiration=account['email_2fa_expiration'])


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect(url_for('login'))
        if 'mfa_enabled' in session and session['mfa_enabled'] and 'mfa_verified' not in session:
            return redirect(url_for('mfa_verify'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/setup_face_recognition_verify', methods=['GET', 'POST'])
@login_required
def setup_face_recognition_verify():
    if request.method == 'POST':
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT password FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        if account and check_password_hash(account['password'], password):
            session['face_recognition_verified'] = True
            return redirect(url_for('setup_face_recognition'))
        else:
            flash('Incorrect password. Please try again.')
            return redirect(url_for('account'))
    return render_template('account.html')


@app.route('/setup_face_recognition', methods=['GET', 'POST'])
@login_required
def setup_face_recognition():
    msg = ''
    if request.method == 'POST':
        face_image_data = request.form.get('face_image_data')
        face_image_file = request.files.get('face_image_file')

        face_image_filename = None

        if face_image_data or face_image_file:
            face_image_filename = os.path.join(app.config['FACE_IMAGES_FOLDER'], f'{session["username"]}.jpg')
            if face_image_data:
                face_image_data = face_image_data.split(',')[1]
                face_image = base64.b64decode(face_image_data)
                with open(face_image_filename, 'wb') as f:
                    f.write(face_image)
            elif face_image_file:
                face_image_file.save(face_image_filename)

            # Check if the image contains a face
            if not detect_face(face_image_filename):
                msg = 'No recognizable face detected in the uploaded image. Please try again.'
                # Delete the invalid face image file
                if os.path.exists(face_image_filename):
                    os.remove(face_image_filename)
                return render_template('setup_face_recognition.html', msg=msg)

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE users SET face_image = %s WHERE id = %s', (face_image_filename, session['id']))
            mysql.connection.commit()
            log_action(session['username'], 'Updated face recognition setup')
            flash('Face recognition setup updated successfully.')
            return redirect(url_for('account'))
        else:
            msg = 'No image data provided. Please upload an image or use the webcam.'

    return render_template('setup_face_recognition.html', msg=msg)



@app.route('/home')
@login_required
def home():
    if 'locked' in session:
        return redirect(url_for('unlock_session'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch user files
    cursor.execute('SELECT id, filename FROM files WHERE user_id = %s', (session['id'],))
    files = cursor.fetchall()

    # Fetch group files and user role in the group
    cursor.execute('''
        SELECT gf.id, gf.filename, ug.name as group_name, gm.role
        FROM group_files gf
        JOIN users_groups ug ON gf.group_id = ug.id
        JOIN group_memberships gm ON gm.group_id = ug.id
        WHERE gm.user_id = %s
    ''', (session['id'],))
    group_files = cursor.fetchall()

    cursor.close()
    return render_template('home.html', username=session['username'], files=files, group_files=group_files)



@app.route('/logout')
def logout():
    log_user_action(session['username'], session['session_id'], 'Logged out')
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('mfa_verified', None)
    process_log_file("user_actions.log")
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT password, mfa_enabled, mfa_method, phone_number, phone_verified FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()

    if request.method == 'POST':
        action = request.form.get('action')

        # Check if 'password' key exists in form data
        if 'password' not in request.form:
            flash('Password is required.')
            return redirect(url_for('account'))

        password = request.form['password']

        if account and check_password_hash(account['password'], password):
            print("Ok can")
            if action == 'save_mfa':
                mfa_method = request.form['mfa_method']
                if mfa_method == 'app':
                    mfa_secret = generate_mfa_secret()
                    session['mfa_secret'] = mfa_secret
                    session['username'] = session['username']  # Ensures the username is set in the session
                    return redirect(url_for('setup_mfa'))
                elif mfa_method == 'email':
                    cursor.execute(
                        'UPDATE users SET mfa_secret = NULL, mfa_enabled = %s, mfa_method = %s WHERE id = %s',
                        (True, mfa_method, session['id']))
                    mysql.connection.commit()
                    session.clear()
                    flash('Email 2FA setup successful. Please log in again.')
                    return redirect(url_for('mfa_success', mfa_method='email'))
                elif mfa_method == 'sms' and account['phone_verified']:
                    cursor.execute(
                        'UPDATE users SET mfa_secret = NULL, mfa_enabled = %s, mfa_method = %s WHERE id = %s',
                        (True, mfa_method, session['id']))
                    mysql.connection.commit()
                    session.clear()
                    flash('SMS 2FA setup successful. Please log in again.')
                    return redirect(url_for('mfa_success', mfa_method='sms'))
                elif mfa_method == 'none':
                    cursor.execute(
                        'UPDATE users SET mfa_secret = NULL, mfa_enabled = %s, mfa_method = %s WHERE id = %s',
                        (False, mfa_method, session['id']))
                    mysql.connection.commit()
                    session.clear()
                    flash('MFA has been disabled for your account.')
                    return redirect(url_for('mfa_disabled_success'))
            elif action == 'verify_phone':
                phone_number = request.form['phone_number']
                phone_verification_code = request.form.get('phone_verification_code')

                if not account['phone_verified']:
                    if not phone_verification_code:
                        verification_code = generate_phone_verification_code()
                        cursor.execute('UPDATE users SET phone_number = %s, phone_verification_code = %s WHERE id = %s',
                                       (phone_number, verification_code, session['id']))
                        mysql.connection.commit()
                        send_sms(phone_number, f"Your verification code is: {verification_code}")
                        flash('Verification code sent to your phone.')
                        return redirect(url_for('account'))
                    else:
                        cursor.execute('SELECT phone_verification_code FROM users WHERE id = %s', (session['id'],))
                        db_verification_code = cursor.fetchone()['phone_verification_code']
                        if phone_verification_code == db_verification_code:
                            cursor.execute(
                                'UPDATE users SET phone_verified = %s, phone_verification_code = NULL WHERE id = %s',
                                (True, session['id']))
                            mysql.connection.commit()
                            flash('Phone number verified successfully.')
                        else:
                            flash('Invalid verification code. Please try again.')
        else:
            flash('Incorrect password. Please try again.')
            return redirect(url_for('account'))



    return render_template('account.html', mfa_enabled=account['mfa_enabled'], mfa_method=account['mfa_method'],
                           phone_number=account['phone_number'], phone_verified=account['phone_verified'])

@app.route('/phone_verification_success')
def phone_verification_success():
    return render_template('phone_verification_success.html')

@app.route('/verify_phone', methods=['POST'])
@login_required
def verify_phone():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT password FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()

    password = request.form['password']
    if account and check_password_hash(account['password'], password):
        print("ok can")
    else:
        flash('Incorrect current password. Please try again.')
        return redirect(url_for('account'))

    phone_number = request.form['phone_number']

    # Check if the phone number is already linked to another account
    cursor.execute('SELECT id FROM users WHERE phone_number = %s AND phone_verified = TRUE', (phone_number,))
    existing_account = cursor.fetchone()

    if existing_account:
        flash('This phone number is already linked to another account.')
        return redirect(url_for('account'))

    if not is_valid_phone_number(phone_number):
        flash('Invalid phone number format. Please enter a valid phone number.')
        return redirect(url_for('account'))

    verification_code = generate_phone_verification_code()

    cursor.execute(
        'UPDATE users SET phone_number = %s, phone_verified = %s, phone_verification_code = %s WHERE id = %s',
        (phone_number, False, verification_code, session['id']))
    mysql.connection.commit()

    try:
        send_sms(phone_number, f"Your verification code is: {verification_code}")
        flash('Verification code sent to your phone.')
    except Exception as e:
        flash(f"Failed to send verification code: {e}")
    return redirect(url_for('account'))

@app.route('/confirm_phone', methods=['POST'])
@login_required
def confirm_phone():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT phone_verification_code FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()

    # Check if the phone number is already linked to another account
    phone_number = request.form.get('phone_number')
    cursor.execute('SELECT id FROM users WHERE phone_number = %s AND phone_verified = TRUE', (phone_number,))
    existing_account = cursor.fetchone()

    if existing_account:
        flash('This phone number is already linked to another account.')
        return redirect(url_for('account'))

    if account['phone_verification_code'] == request.form['verification_code']:
        cursor.execute('UPDATE users SET phone_verified = %s, phone_verification_code = NULL WHERE id = %s',
                       (True, session['id']))
        mysql.connection.commit()
        flash('Phone number verified successfully.')
    else:
        flash('Invalid verification code. Please try again.')

    return redirect(url_for('account'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_new_password = request.form['confirm_new_password']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT password FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()

    # Check if the current password is correct
    if account and check_password_hash(account['password'], current_password):
        print("ok can")
    else:
        flash('Incorrect current password. Please try again.')
        return redirect(url_for('account'))

    # Check if the new passwords match
    if new_password != confirm_new_password:
        flash('New passwords do not match. Please try again.')
        return redirect(url_for('account'))

    # Check if the new password meets the criteria
    if len(new_password) < 8 or not re.search(r"[A-Za-z]", new_password) or not re.search(r"[0-9]",
                                                                                          new_password) or not re.search(
            r"[!@#$%^&*]", new_password):
        flash('New password must be at least 8 characters long, contain letters, numbers, and special characters.')
        return redirect(url_for('account'))

    # Retrieve previous passwords from the database
    cursor.execute('SELECT password_hash FROM previous_passwords WHERE user_id = %s', (session['id'],))
    previous_passwords = cursor.fetchall()

    # Check if the new password is the same as any previous passwords
    for previous_password in previous_passwords:
        if check_password_hash(previous_password['password_hash'], new_password):
            flash(
                'New password cannot be the same as any of the previous passwords. Please choose a different password.')
            return redirect(url_for('account'))

    # Hash the new password and update the user's password
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    cursor.execute('INSERT INTO previous_passwords (user_id, password_hash) VALUES (%s, %s)',
                   (session['id'], account['password']))
    cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, session['id']))
    mysql.connection.commit()

    # Clear the session and prompt the user to log in again
    session.clear()
    flash('Password changed successfully. Please log in with your new password.')
    log_action(session.get('username', 'Unknown'), 'Password changed')
    return redirect(url_for('password_change_success'))

@app.route('/password_change_success')
def password_change_success():
    return render_template('password_change_success.html')

@app.route('/mfa_disabled_success')
def mfa_disabled_success():
    return render_template('mfa_disabled_success.html')

def save_file(file_path, user_id, filename, replace=False):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(user_folder, exist_ok=True)

    new_filename = filename  # Initialize new_filename with the original filename
    final_filepath = os.path.join(user_folder, new_filename)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if replace:
        # Remove the old entry from the database before replacing the file
        cursor.execute('DELETE FROM files WHERE filename = %s AND user_id = %s', (filename, user_id))
        mysql.connection.commit()
        os.replace(file_path, final_filepath)
    else:
        # Check if filename already exists and rename if necessary
        base, extension = os.path.splitext(filename)
        counter = 1
        while os.path.exists(final_filepath):
            new_filename = f"{base} ({counter}){extension}"
            final_filepath = os.path.join(user_folder, new_filename)
            counter += 1
        os.rename(file_path, final_filepath)

    encrypted_filepath = encrypt_path(final_filepath)
    cursor.execute('INSERT INTO files (user_id, filename, filepath) VALUES (%s, %s, %s)', (user_id, new_filename, encrypted_filepath))
    mysql.connection.commit()
    return new_filename


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'

        file = request.files['file']

        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            temp_filepath = os.path.join(app.config['TEMP_FOLDER'], filename)
            file.save(temp_filepath)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT email, email_2fa_code, email_2fa_expiration FROM users WHERE id = %s',
                           (session['id'],))
            account = cursor.fetchone()
            # Scan the file for viruses
            user_email = account['email']
            print(user_email)# Assuming the user's email is stored in the session
            if not scan_file(temp_filepath, user_email):
                os.remove(temp_filepath)
                return 'File is infected and cannot be uploaded.'

            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['id']))
            if os.path.exists(os.path.join(user_folder, filename)):
                return render_template('upload_confirm.html', filename=filename, temp_filepath=temp_filepath)
            else:
                new_filename = save_file(temp_filepath, session['id'], filename)
                return render_template('upload_success.html', filename=new_filename)
        else:
            return 'Invalid file type. Only PDF and DOCX files are allowed.'
    return render_template('upload.html')
@app.route('/upload_confirm', methods=['POST'])
@login_required
def upload_confirm():
    filename = request.form['filename']
    action = request.form['action']
    temp_filepath = request.form['temp_filepath']

    if action == 'replace':
        new_filename = save_file(temp_filepath, session['id'], filename, replace=True)
    else:
        new_filename = save_file(temp_filepath, session['id'], filename)

    return render_template('upload_success.html', filename=new_filename)

@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT filename, filepath FROM files WHERE id = %s AND user_id = %s', (file_id, session['id']))
    file = cursor.fetchone()
    if file:
        decrypted_filepath = decrypt_path(file['filepath'])
        return send_from_directory(directory=os.path.dirname(decrypted_filepath), path=os.path.basename(decrypted_filepath))
    else:
        return 'File not found or you do not have permission to view this file.'

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT filename, filepath FROM files WHERE id = %s AND user_id = %s', (file_id, session['id']))
    file = cursor.fetchone()
    if file:
        decrypted_filepath = decrypt_path(file['filepath'])
        return send_from_directory(directory=os.path.dirname(decrypted_filepath), path=os.path.basename(decrypted_filepath), as_attachment=True)
    else:
        return 'File not found or you do not have permission to download this file.'

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT filepath FROM files WHERE id = %s AND user_id = %s', (file_id, session['id']))
    file = cursor.fetchone()
    if file:
        decrypted_filepath = decrypt_path(file['filepath'])
        os.remove(decrypted_filepath)
        cursor.execute('DELETE FROM files WHERE id = %s AND user_id = %s', (file_id, session['id']))
        mysql.connection.commit()
        return redirect(url_for('home'))
    else:
        return 'File not found or you do not have permission to delete this file.'


@app.route('/mfa_verify_sms', methods=['GET', 'POST'])
def mfa_verify_sms():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT phone_number, sms_2fa_code, sms_2fa_expiration FROM users WHERE id = %s', (session['id'],))
    account = cursor.fetchone()
    if not account:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'resend' in request.form:
            generate_and_send_sms_2fa_code(session['id'], account['phone_number'])
            flash('A new 2FA code has been sent to your phone.')
            return redirect(url_for('mfa_verify_sms'))

        code = request.form.get('sms_2fa_code')
        if account['sms_2fa_code'] == code and account['sms_2fa_expiration'] > datetime.utcnow():
            cursor.execute('UPDATE users SET sms_2fa_code = NULL, sms_2fa_expiration = NULL WHERE id = %s', (session['id'],))
            mysql.connection.commit()
            session['mfa_verified'] = True
            return redirect(url_for('home'))
        else:
            flash('Invalid or expired 2FA code. Please try again.')

    return render_template('mfa_verify_sms.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT email, phone_verified FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            options = {'email': True, 'phone': account['phone_verified']}
            return render_template('forgot_password.html', options=options, username=username)
        else:
            flash('Username not found.')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    username = request.form['username']
    otp_method = request.form['otp_method']
    otp_code = generate_otp_code()
    expiration = datetime.utcnow() + timedelta(minutes=5)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE users SET otp_code = %s, otp_expiration = %s WHERE username = %s',
                   (otp_code, expiration, username))
    mysql.connection.commit()

    cursor.execute('SELECT email, phone_number FROM users WHERE username = %s', (username,))
    account = cursor.fetchone()

    session['otp_method'] = otp_method

    if otp_method == 'email':
        send_otp_email(account['email'], otp_code)
    elif otp_method == 'phone' and account['phone_number']:
        send_otp_sms(account['phone_number'], otp_code)

    flash('OTP sent successfully.')
    session['username'] = username  # Store username in session for verification step
    return redirect(url_for('verify_otp'))

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        username = session.get('username')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT otp_code, otp_expiration FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            otp_expiration = account['otp_expiration'].replace(tzinfo=timezone.utc)
            if otp == account['otp_code'] and datetime.now(timezone.utc) <= otp_expiration:
                session['otp_verified'] = True
                cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                session['id'] = user['id']  # Ensure session['id'] is set here
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid or expired OTP code.')

    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'otp_verified' not in session or 'id' not in session:
        flash('OTP verification required.')
        return redirect(url_for('forgot_password'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    username = session.get('username')

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the new passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password'))

        # Check if the new password meets the criteria
        if len(new_password) < 8 or not re.search(r"[A-Za-z]", new_password) or not re.search(r"[0-9]", new_password) or not re.search(r"[!@#$%^&*]", new_password):
            flash('New password must be at least 8 characters long, contain letters, numbers, and special characters.')
            return redirect(url_for('reset_password'))

        # Retrieve previous passwords from the database
        cursor.execute('SELECT password_hash FROM previous_passwords WHERE user_id = %s', (session['id'],))
        previous_passwords = cursor.fetchall()

        # Check if the new password is the same as any previous passwords
        for previous_password in previous_passwords:
            if check_password_hash(previous_password['password_hash'], new_password):
                flash('New password cannot be the same as any of the previous passwords. Please choose a different password.')
                return redirect(url_for('reset_password'))

        # Hash the new password and update the user's password
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute('INSERT INTO previous_passwords (user_id, password_hash) VALUES (%s, %s)',
                       (session['id'], hashed_password))
        cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_password, username))
        mysql.connection.commit()

        flash('Password changed successfully.')
        session.clear()
        return redirect(url_for('password_change_success'))

    return render_template('reset_password.html')

@app.route('/resend_forgot_password_otp', methods=['POST'])
def resend_forgot_password_otp():
    username = session.get('username')
    otp_method = session.get('otp_method')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT email, phone_number, phone_verified FROM users WHERE username = %s', (username,))
    account = cursor.fetchone()

    if account:
        otp_code = generate_otp_code()
        expiration = datetime.utcnow() + timedelta(minutes=5)
        cursor.execute('UPDATE users SET otp_code = %s, otp_expiration = %s WHERE username = %s',
                       (otp_code, expiration, username))
        mysql.connection.commit()

        if otp_method == 'phone' and account['phone_verified']:
            send_otp_sms(account['phone_number'], otp_code)
        else:
            send_otp_email(account['email'], otp_code)

        flash('OTP resent successfully.')
    else:
        flash('Username not found.')

    return redirect(url_for('verify_otp'))


@app.route('/phone_login', methods=['GET', 'POST'])
def phone_login():
    if request.method == 'POST':
        phone_number = request.form['phone_number']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT id, username FROM users WHERE phone_number = %s AND phone_verified = TRUE', (phone_number,))
        account = cursor.fetchone()

        if account:
            otp_code = generate_otp_code()
            expiration = datetime.utcnow() + timedelta(minutes=5)
            cursor.execute('UPDATE users SET otp_code = %s, otp_expiration = %s WHERE id = %s',
                           (otp_code, expiration, account['id']))
            mysql.connection.commit()
            send_otp_sms(phone_number, otp_code)
            session['phone_number'] = phone_number
            flash('OTP sent successfully.')
            return redirect(url_for('verify_phone_otp'))
        else:
            flash('Phone number not found or not verified.')
            return redirect(url_for('phone_login'))

    return render_template('phone_login.html')


@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    phone_number = session.get('phone_number')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT id, username FROM users WHERE phone_number = %s AND phone_verified = TRUE', (phone_number,))
    account = cursor.fetchone()

    if account:
        otp_code = generate_otp_code()
        expiration = datetime.utcnow() + timedelta(minutes=5)
        cursor.execute('UPDATE users SET otp_code = %s, otp_expiration = %s WHERE id = %s',
                       (otp_code, expiration, account['id']))
        mysql.connection.commit()
        send_otp_sms(phone_number, otp_code)
        flash('OTP resent successfully.')
    else:
        flash('Phone number not found or not verified.')

    return redirect(url_for('verify_phone_otp'))


@app.route('/verify_phone_otp', methods=['GET', 'POST'])
def verify_phone_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        phone_number = session.get('phone_number')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT id, username, otp_code, otp_expiration FROM users WHERE phone_number = %s', (phone_number,))
        account = cursor.fetchone()

        if account and otp == account['otp_code'] and datetime.utcnow() <= account['otp_expiration']:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['mfa_verified'] = True
            flash('Login successful.')
            return redirect(url_for('home'))
        else:
            flash('Invalid or expired OTP code.')

    return render_template('verify_phone_otp.html')

# Utility to get Google's provider configuration
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/google_login")
def google_login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri="https://127.0.0.1:5000/google_login/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/google_login/callback")
def callback():
    try:
        # Get authorization code Google sent back to you
        code = request.args.get("code")

        if not code:
            flash('Access denied: authentication failed.', 'error')
            return redirect(url_for('login'))

        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]

        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )

        client.parse_request_body_response(json.dumps(token_response.json()))

        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        if userinfo_response.json().get("email_verified"):
            unique_id = userinfo_response.json()["sub"]
            users_email = userinfo_response.json()["email"]
            picture = userinfo_response.json()["picture"]
            users_name = userinfo_response.json()["given_name"]

            # Check if user exists in the database
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM users WHERE email = %s', (users_email,))
            account = cursor.fetchone()

            if not account:
                # User does not exist, create new user
                session['username_prompt'] = True
                session['unique_id'] = unique_id
                session['email'] = users_email
                session['name'] = users_name
                return redirect(url_for('complete_google_signup'))

            # Log in user
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['session_id'] = hashlib.sha256(os.urandom(64)).hexdigest()

            # Check if MFA is enabled and redirect accordingly
            if account['mfa_enabled']:
                session['mfa_enabled'] = account['mfa_enabled']
                session['mfa_method'] = account['mfa_method']
                if account['mfa_method'] == 'app':
                    session['mfa_secret'] = account['mfa_secret']
                    return redirect(url_for('mfa_verify'))
                elif account['mfa_method'] == 'email':
                    code = generate_2fa_code()
                    expiration = datetime.now() + timedelta(minutes=5)
                    cursor.execute('UPDATE users SET email_2fa_code = %s, email_2fa_expiration = %s WHERE id = %s',
                                   (code, expiration, account['id']))
                    mysql.connection.commit()
                    send_2fa_email(account['email'], code)
                    return redirect(url_for('mfa_verify_email'))
                elif account['mfa_method'] == 'sms' and account['phone_verified']:
                    generate_and_send_sms_2fa_code(account['id'], account['phone_number'])
                    return redirect(url_for('mfa_verify_sms'))

            return redirect(url_for('home'))
        else:
            flash('User email not available or not verified by Google.', 'error')
            return redirect(url_for('login'))
    except oauthlib.oauth2.rfc6749.errors.AccessDeniedError:
        flash('Access denied: authentication failed.', 'error')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login'))


@app.route('/complete_google_signup', methods=['GET', 'POST'])
def complete_google_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate username
        if len(username) > 50:
            flash('Username must be 50 characters or fewer.', 'error')
            return render_template('complete_google_signup.html')

        # Validate password
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('complete_google_signup.html')

        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[\W_]', password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.', 'error')
            return render_template('complete_google_signup.html')

        # Ensure username is not taken
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already taken, please choose another one.', 'error')
            return render_template('complete_google_signup.html')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        # Create user in database and set email_verified to True
        cursor.execute('INSERT INTO users (username, email, password, email_verified) VALUES (%s, %s, %s, %s)', (username, session['email'], hashed_password, True))
        mysql.connection.commit()

        # Log in user
        cursor.execute('SELECT * FROM users WHERE email = %s', (session['email'],))
        account = cursor.fetchone()
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = username

        # Check if MFA is enabled and redirect accordingly
        if account['mfa_enabled']:
            session['mfa_enabled'] = account['mfa_enabled']
            session['mfa_method'] = account['mfa_method']
            if account['mfa_method'] == 'app':
                session['mfa_secret'] = account['mfa_secret']
                return redirect(url_for('mfa_verify'))
            elif account['mfa_method'] == 'email':
                code = generate_2fa_code()
                expiration = datetime.now() + timedelta(minutes=5)
                cursor.execute('UPDATE users SET email_2fa_code = %s, email_2fa_expiration = %s WHERE id = %s',
                               (code, expiration, account['id']))
                mysql.connection.commit()
                send_2fa_email(account['email'], code)
                return redirect(url_for('mfa_verify_email'))
            elif account['mfa_method'] == 'sms' and account['phone_verified']:
                generate_and_send_sms_2fa_code(account['id'], account['phone_number'])
                return redirect(url_for('mfa_verify_sms'))

        session.pop('username_prompt', None)
        session.pop('unique_id', None)
        session.pop('email', None)
        session.pop('name', None)

        return redirect(url_for('home'))

    return render_template('complete_google_signup.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    msg = ''
    # Initialize or increment the failed attempts count
    if 'admin_failed_attempts' not in session:
        session['admin_failed_attempts'] = 0

    if session['admin_failed_attempts'] >= 5:
        print("Too many failed attempts. Terminating the program.")
        sys.exit("Program terminated due to too many failed login attempts.")

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username'].strip()
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            if account['role'] != 'admin':
                msg = 'Unauthorized access for this role. Please use the user login page.'
            else:
                session['admin_id'] = account['id']
                session['loggedin'] = True
                session['username'] = account['username']
                session['role'] = account['role']
                session['session_id'] = hashlib.sha256(os.urandom(64)).hexdigest()
                session['regenerate_time'] = datetime.now()

                session.pop('admin_failed_attempts', None)  # Reset failed attempts
                log_user_action(session['username'], session['session_id'], 'Logged in')
                return redirect(url_for('admin_dashboard'))
        else:
            session['admin_failed_attempts'] += 1
            if session['admin_failed_attempts'] >= 5:
                print("Too many failed attempts. Terminating the program.")
                sys.exit("Program terminated due to too many failed login attempts.")
            else:
                msg = 'Invalid credentials or unauthorized access'

    return render_template('admin_login.html', msg=msg)

@app.route('/admin/group/delete/<int:group_id>', methods=['POST'])
@login_required
def admin_delete_group(group_id):
    if session.get('role') != 'admin':
        return redirect(url_for('home'))

    cursor = mysql.connection.cursor()

    try:
        cursor.execute('DELETE FROM group_files WHERE group_id = %s', (group_id,))
        cursor.execute('DELETE FROM users_groups WHERE id = %s', (group_id,))
        mysql.connection.commit()
        flash('Group and its files deleted successfully', 'success')
    except MySQLdb.Error as e:
        mysql.connection.rollback()
        flash(f'Error deleting group: {str(e)}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/group/file/delete/<int:file_id>', methods=['POST'])
@login_required
def admin_delete_group_file(file_id):
    if session.get('role') != 'admin':
        return redirect(url_for('home'))

    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM group_files WHERE id = %s', (file_id,))
    mysql.connection.commit()
    cursor.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if 'locked' in session:
        return redirect(url_for('admin_unlock_session'))

    if session.get('role') != 'admin':
        return redirect(url_for('home'))

    search_query = ''
    users = []
    files = []

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        search_query = request.form.get('search_query')
        cursor.execute('SELECT id, username, email FROM users WHERE username = %s OR email = %s', (search_query, search_query))
        users = cursor.fetchall()

        if users:
            user_ids = [user['id'] for user in users]
            cursor.execute('SELECT * FROM files WHERE user_id IN (%s)' % ','.join(['%s'] * len(user_ids)), user_ids)
            files = cursor.fetchall()

    # Fetch all groups
    cursor.execute('SELECT * FROM users_groups')
    groups = cursor.fetchall()

    # Fetch files for each group
    for group in groups:
        cursor.execute('SELECT * FROM group_files WHERE group_id = %s', (group['id'],))
        group['files'] = cursor.fetchall()

    cursor.close()

    return render_template('admin_dashboard.html', users=users, files=files, search_query=search_query, groups=groups)




@app.route('/admin_files', methods=['GET', 'POST'])
def admin_files():
    if 'role' in session and session['role'] == 'admin':
        files = []
        search_query = ''
        error_msg = None

        if request.method == 'POST':
            search_query = request.form.get('search_query')
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM files WHERE filename LIKE %s', ('%' + search_query + '%',))
            files = cursor.fetchall()
            cursor.close()

            if not files:
                error_msg = 'No files found for the search query.'

        return render_template('admin_files.html', files=files, search_query=search_query, error_msg=error_msg)
    return redirect(url_for('login'))


@app.route('/confirm_delete_user', methods=['POST'])
def confirm_delete_user():
    if 'role' in session and session['role'] == 'admin':
        user_id = request.form.get('delete')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        print(cursor)
        cursor.close()

        if user:
            return render_template('confirm_delete_user.html', user=user)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user', methods=['POST'])
@login_required
def delete_user():
    if session.get('role') != 'admin':
        return redirect(url_for('home'))

    user_id = request.form.get('user_id')

    print(f'Deleting user with ID: {user_id}')

    if not user_id:
        flash('No user specified for deletion', 'danger')
        return redirect(url_for('admin_dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Fetch the username and face image file path
        cursor.execute('SELECT username, face_image FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()

        # Prevent deletion of the 'admin' user
        if user and user['username'] == 'admin':
            flash('The admin user cannot be deleted.', 'danger')
            return redirect(url_for('admin_dashboard'))

        if user and user['face_image']:
            face_image_path = user['face_image']
            if os.path.exists(face_image_path):
                os.remove(face_image_path)

        # Delete associated records in the devices table
        cursor.execute('DELETE FROM devices WHERE user_id = %s', (user_id,))
        # Delete associated records in the files table
        cursor.execute('DELETE FROM files WHERE user_id = %s', (user_id,))
        # Now delete the user
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        mysql.connection.commit()
        flash('User and their files deleted successfully', 'success')
    except MySQLdb.IntegrityError as e:
        mysql.connection.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/confirm_delete_file', methods=['POST'])
def confirm_delete_file():
    if 'role' in session and session['role'] == 'admin':
        file_id = request.form.get('delete')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM files WHERE id = %s', (file_id,))
        file = cursor.fetchone()
        cursor.close()

        if file:
            return render_template('confirm_delete_file.html', file=file)
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def admin_delete_file(file_id):
    print(f"Attempting to delete file with id: {file_id}")
    if 'role' in session and session['role'] == 'admin':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM files WHERE id = %s', (file_id,))
        mysql.connection.commit()
        cursor.close()
        flash('File deleted successfully.')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/home')
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        return render_template('home.html')
    return redirect(url_for('login'))

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    error_message = None

    if request.method == 'POST':
        group_name = request.form['group_name']
        created_by = session['id']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users_groups WHERE name = %s', (group_name,))
        existing_group = cursor.fetchone()

        if existing_group:
            error_message = 'Group name is already in use. Please choose a different name.'
        else:
            # Insert the new group
            cursor.execute('INSERT INTO users_groups (name, created_by) VALUES (%s, %s)', (group_name, created_by))
            mysql.connection.commit()

            # Get the id of the newly created group
            group_id = cursor.lastrowid

            # Insert the creator into group_memberships as the group_leader
            cursor.execute('INSERT INTO group_memberships (group_id, user_id, role) VALUES (%s, %s, %s)',
                           (group_id, created_by, 'group_leader'))
            mysql.connection.commit()

            cursor.close()
            return redirect(url_for('view_groups'))

        cursor.close()

    return render_template('create_group.html', error_message=error_message)

@app.route('/view_groups')
@login_required
def view_groups():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch groups the user leads
    cursor.execute('''
        SELECT ug.id, ug.name, ug.is_active
        FROM users_groups ug
        WHERE ug.created_by = %s
    ''', (session['id'],))
    groups = cursor.fetchall()
    print(f'Groups led by user: {groups}')

    # Fetch groups the user is a member of or a leader of but not the creator
    cursor.execute('''
        SELECT ug.id, ug.name, ug.is_active
        FROM users_groups ug
        JOIN group_memberships gm ON ug.id = gm.group_id
        WHERE gm.user_id = %s AND (gm.role != 'group_leader' OR ug.created_by != %s)
    ''', (session['id'], session['id']))
    member_groups = cursor.fetchall()
    print(f'Groups user is a member of: {member_groups}')

    cursor.close()
    return render_template('view_groups.html', groups=groups, member_groups=member_groups)


@app.route('/disable_group/<int:group_id>', methods=['POST'])
def disable_group(group_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE users_groups SET is_active = FALSE WHERE id = %s AND created_by = %s', (group_id, session['id']))
    mysql.connection.commit()
    cursor.close()

    flash('Group disabled successfully!', 'success')
    return redirect(url_for('view_groups'))

@app.route('/enable_group/<int:group_id>', methods=['POST'])
def enable_group(group_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE users_groups SET is_active = TRUE WHERE id = %s AND created_by = %s', (group_id, session['id']))
    mysql.connection.commit()
    cursor.close()

    flash('Group enabled successfully!', 'success')
    return redirect(url_for('view_groups'))

@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM users_groups WHERE id = %s AND created_by = %s', (group_id, session['id']))
    mysql.connection.commit()
    cursor.close()

    flash('Group deleted successfully!', 'success')
    return redirect(url_for('view_groups'))

@app.route('/invite_user/<int:group_id>', methods=['GET', 'POST'])
def invite_user(group_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users_groups WHERE id = %s AND created_by = %s', (group_id, session['id']))
    group = cursor.fetchone()

    if not group:
        flash('Group not found.', 'danger')
        return redirect(url_for('view_groups'))

    if not group['is_active']:
        flash('This group is currently disabled and cannot accept invitations.', 'danger')
        return redirect(url_for('view_groups'))

    error_message = None
    if request.method == 'POST':
        invitee_username = request.form['invitee_username']
        cursor.execute('SELECT * FROM users WHERE username = %s', (invitee_username,))
        invitee = cursor.fetchone()

        if not invitee:
            error_message = 'No user found with that username.'
        else:
            cursor.execute(
                'INSERT INTO group_invitations (group_id, inviter_id, invitee_username) VALUES (%s, %s, %s)',
                (group_id, session['id'], invitee_username))
            mysql.connection.commit()
            flash('Invitation sent successfully!', 'success')
            return redirect(url_for('view_groups'))

    cursor.close()
    return render_template('invite_user.html', group=group, error_message=error_message)

@app.route('/invitations')
def view_invitations():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT gi.*, ug.name AS group_name, u.username AS inviter_name '
                   'FROM group_invitations gi '
                   'JOIN users_groups ug ON gi.group_id = ug.id '
                   'JOIN users u ON gi.inviter_id = u.id '
                   'WHERE gi.invitee_username = %s AND gi.status = "pending"', (session['username'],))
    invitations = cursor.fetchall()
    cursor.close()

    return render_template('view_invitations.html', invitations=invitations)

@app.route('/respond_invitation/<int:invitation_id>/<string:response>', methods=['POST'])
def respond_invitation(invitation_id, response):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM group_invitations WHERE id = %s AND invitee_username = %s AND status = "pending"',
                   (invitation_id, session['username']))
    invitation = cursor.fetchone()

    if not invitation:
        flash('Invalid invitation.', 'danger')
        return redirect(url_for('view_invitations'))

    if response == 'accept':
        cursor.execute('UPDATE group_invitations SET status = "accepted" WHERE id = %s', (invitation_id,))
        cursor.execute('INSERT INTO group_memberships (group_id, user_id, role) VALUES (%s, %s, %s)',
                       (invitation['group_id'], session['id'], 'group_user'))
        flash('Invitation accepted.', 'success')
    elif response == 'decline':
        cursor.execute('UPDATE group_invitations SET status = "declined" WHERE id = %s', (invitation_id,))
        flash('Invitation declined.', 'success')

    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('view_invitations'))

def save_group_file(temp_filepath, group_id, filename, replace=False):
    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'group_' + str(group_id))
    os.makedirs(group_folder, exist_ok=True)
    filepath = os.path.join(group_folder, filename)
    if replace or not os.path.exists(filepath):
        os.rename(temp_filepath, filepath)
    return filename

@app.route('/group_upload/<int:group_id>', methods=['GET', 'POST'])
def group_upload(group_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users_groups WHERE id = %s', (group_id,))
    group = cursor.fetchone()

    if request.method == 'POST':
        # Check if the group is active
        if not group['is_active']:
            flash('Cannot upload files to a disabled group.', 'danger')
            return redirect(url_for('view_groups'))

        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            group_folder = os.path.join('uploads/groups', f'group_{group_id}')
            os.makedirs(group_folder, exist_ok=True)
            file.save(os.path.join(group_folder, filename))

            cursor.execute('INSERT INTO group_files (group_id, filename, filepath, uploaded_by) VALUES (%s, %s, %s, %s)',
                           (group_id, filename, os.path.join(group_folder, filename), session['id']))
            mysql.connection.commit()
            flash('File successfully uploaded', 'success')
            return redirect(url_for('view_groups'))

    return render_template('group_upload.html', group=group)

@app.route('/group_upload_confirm', methods=['POST'])
@login_required
def group_upload_confirm():
    filename = request.form['filename']
    action = request.form['action']
    temp_filepath = request.form['temp_filepath']
    group_id = request.form['group_id']

    if action == 'replace':
        new_filename = save_group_file(temp_filepath, group_id, filename, replace=True)
    else:
        new_filename = save_group_file(temp_filepath, group_id, filename)

    return render_template('group_upload_success.html', filename=new_filename, group_id=group_id)

@app.route('/group_view_file/<int:file_id>', methods=['GET'])
@login_required
def group_view_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('''
        SELECT gf.*, ug.name as group_name, gm.role
        FROM group_files gf
        JOIN users_groups ug ON gf.group_id = ug.id
        JOIN group_memberships gm ON gm.group_id = ug.id
        WHERE gf.id = %s AND gm.user_id = %s
    ''', (file_id, session['id']))
    file = cursor.fetchone()
    cursor.close()

    if file:
        return send_file(file['filepath'])
    else:
        flash('File not found or you do not have permission to view this file.', 'danger')
        return redirect(url_for('home'))

@app.route('/group_download_file/<int:file_id>')
@login_required
def group_download_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch group file
    cursor.execute('''
        SELECT gf.filename, gf.filepath
        FROM group_files gf
        JOIN group_memberships gm ON gf.group_id = gm.group_id
        WHERE gf.id = %s AND gm.user_id = %s
    ''', (file_id, session['id']))
    file = cursor.fetchone()

    if file:
        return send_from_directory(directory=os.path.dirname(file['filepath']), path=os.path.basename(file['filepath']),
                                   as_attachment=True)

    return 'File not found or you do not have permission to download this file.'

@app.route('/group_delete_file/<int:file_id>')
@login_required
def group_delete_file(file_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch group file and ensure the user is the group leader
    cursor.execute('''
        SELECT gf.filepath
        FROM group_files gf
        JOIN group_memberships gm ON gf.group_id = gm.group_id
        WHERE gf.id = %s AND gm.user_id = %s AND gm.role = 'group_leader'
    ''', (file_id, session['id']))
    file = cursor.fetchone()

    if file:
        os.remove(file['filepath'])
        cursor.execute('DELETE FROM group_files WHERE id = %s', (file_id,))
        mysql.connection.commit()
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found or you do not have permission to delete this file.', 'danger')

    cursor.close()
    return redirect(url_for('home'))

@app.route('/leave_group/<int:group_id>', methods=['POST'])
@login_required
def leave_group(group_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if the user is a member of the group
    cursor.execute('SELECT * FROM group_memberships WHERE group_id = %s AND user_id = %s', (group_id, session['id']))
    membership = cursor.fetchone()

    if membership:
        # Remove the user from the group
        cursor.execute('DELETE FROM group_memberships WHERE group_id = %s AND user_id = %s', (group_id, session['id']))
        mysql.connection.commit()
        flash('You have successfully left the group.', 'success')
    else:
        flash('You are not a member of this group.', 'danger')

    cursor.close()
    return redirect(url_for('view_groups'))

@app.route('/elevate_user/<int:group_id>', methods=['GET', 'POST'])
@login_required
def elevate_user(group_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if the current user is the group leader
    cursor.execute('''
        SELECT * FROM group_memberships
        WHERE group_id = %s AND user_id = %s AND role = 'group_leader'
    ''', (group_id, session['id']))
    group_leader = cursor.fetchone()

    if not group_leader:
        flash('You do not have permission to elevate users in this group.', 'danger')
        return redirect(url_for('view_groups'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['role']

        cursor.execute('''
            UPDATE group_memberships
            SET role = %s
            WHERE group_id = %s AND user_id = %s
        ''', (new_role, group_id, user_id))

        mysql.connection.commit()
        flash('User elevated successfully!', 'success')
        return redirect(url_for('view_groups'))

    # Fetch users in the group
    cursor.execute('''
        SELECT u.id, u.username, gm.role
        FROM users u
        JOIN group_memberships gm ON u.id = gm.user_id
        WHERE gm.group_id = %s
    ''', (group_id,))
    group_members = cursor.fetchall()

    cursor.close()
    return render_template('elevate_user.html', group_members=group_members, group_id=group_id)


@app.route('/manage_user_role/<int:group_id>', methods=['GET', 'POST'])
@login_required
def manage_user_role(group_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if the current user is the group leader
    cursor.execute('''
        SELECT * FROM group_memberships
        WHERE group_id = %s AND user_id = %s AND role = 'group_leader'
    ''', (group_id, session['id']))
    group_leader = cursor.fetchone()

    if not group_leader:
        flash('You do not have permission to manage users in this group.', 'danger')
        return redirect(url_for('view_groups'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        new_role = request.form['role']

        # Prevent group leader from changing their own role
        if user_id == str(session['id']):
            flash('You cannot change your own role.', 'danger')
        else:
            cursor.execute('''
                UPDATE group_memberships
                SET role = %s
                WHERE group_id = %s AND user_id = %s
            ''', (new_role, group_id, user_id))

            mysql.connection.commit()
            flash('User role updated successfully!', 'success')
        return redirect(url_for('view_groups'))

    # Fetch users in the group
    cursor.execute('''
        SELECT u.id, u.username, gm.role
        FROM users u
        JOIN group_memberships gm ON u.id = gm.user_id
        WHERE gm.group_id = %s
    ''', (group_id,))
    group_members = cursor.fetchall()

    cursor.close()
    return render_template('manage_user_role.html', group_members=group_members, group_id=group_id)
@app.route('/session_logs', methods=['GET'])
def session_logs():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Get the username from the request
        username = request.args.get('username', '')

        if username:
            # If username is provided, filter the logs by username
            cursor.execute('SELECT * FROM user_session_logs WHERE username = %s', (username,))
        else:
            # If no username is provided, fetch all logs
            cursor.execute('SELECT * FROM user_session_logs')

        session_logs = cursor.fetchall()
        cursor.close()

        # Render template with session logs data
        return render_template('session_logs.html', session_logs=session_logs, search_username=username)

    except mysql.connection.Error as error:
        print(f"Error: {error}")
        return "Error fetching session logs"
def insert_session_log(user_id, session_id, log_in_time, log_out_time, duration):
    try:
        conn = MySQLdb.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        cursor = conn.cursor()

        # Check if the session ID already exists
        cursor.execute("SELECT * FROM user_session_logs WHERE id = %s", (user_id,))
        existing_log = cursor.fetchone()

        if existing_log:
            print("Session ID already exists. Skipping insertion.")
        else:
            sql = "INSERT INTO user_session_logs (username, session_id, log_in_time, log_out_time, duration) VALUES (%s, %s, %s, %s, %s)"
            data = (user_id, session_id, log_in_time, log_out_time, duration)
            cursor.execute(sql, data)
            conn.commit()
            print("Log entry successfully recorded.")

    except MySQLdb.Error as error:
        print(f"Error: {error}")

    finally:
        if 'conn' in locals() and conn.open:
            cursor.close()
            conn.close()
            print("MySQL connection closed.")

def parse_log_line(line):
    try:
        parts = line.split(' - ')

        if len(parts) < 4:
            raise ValueError("Invalid log line format")

        timestamp_str = None
        user_id = None
        session_id = None
        action = None

        for part in parts:
            if part.startswith('Action: '):
                action = part.split(': ')[1].strip()
            elif part.startswith('Username: '):
                user_id = part.split(': ')[1].strip()
            elif part.startswith('Session ID: '):
                session_id = part.split(': ')[1].strip()
            elif ' ' in part:
                try:
                    datetime.strptime(part.strip(), '%Y-%m-%d %H:%M:%S')
                    timestamp_str = part.strip()
                except ValueError:
                    continue

        if not timestamp_str:
            raise ValueError("Timestamp not found in line")

        log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

        return log_time, user_id, session_id, action

    except ValueError as ve:
        print(f"Error parsing line: {ve}. Line: {line}")
        return None, None, None, None
    except Exception as e:
        print(f"Unexpected error: {e}. Line: {line}")
        return None, None, None, None

def process_log_file(log_file_path):
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            log_time, user_id, session_id, action = parse_log_line(line.strip())

            if log_time is None:
                continue

            try:
                if action == 'Logged in':
                    log_in_time = log_time
                    log_out_time = None
                elif action == 'Logged out':
                    log_out_time = log_time
                    if log_in_time:
                        duration = log_out_time - log_in_time
                        insert_session_log(user_id, session_id, log_in_time, log_out_time, duration)
                        log_in_time = None

            except ValueError as e:
                print(f"Error converting timestamp: {e}. Line: {line.strip()}")
            except Exception as e:
                print(f"Unexpected error: {e}. Line: {line.strip()}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def summarize_report(report):
    # Extract relevant information
    file_info = report['meta']['file_info']
    detections = report['data']['attributes']['results']
    stats = report['data']['attributes']['stats']

    # Check if any engine detected a malicious result
    malicious_detected = any(result and result['category'] == 'Malicious' for result in detections.values())

    # Prepare summary based on detection results
    if malicious_detected:
        summary = f"File Information:\n"
        summary += f"SHA256: {file_info['sha256']}\n"
        summary += f"MD5: {file_info['md5']}\n"
        summary += f"SHA1: {file_info['sha1']}\n"
        summary += f"File Size: {file_info['size']} bytes\n\n"

        summary += f"Detection Results:\n"
        for engine, result in detections.items():
            if result is not None:
                summary += f"{engine}: {result['category']} ({result['method']})\n"
            else:
                summary += f"{engine}: No result\n"

        summary += "\nOverall Statistics:\n"
        summary += f"Malicious: {stats['malicious']}\n"
        summary += f"Suspicious: {stats['suspicious']}\n"
        summary += f"Undetected: {stats['undetected']}\n"
        summary += f"Harmless: {stats['harmless']}\n"
        summary += f"Timeout: {stats['timeout']}\n"
        summary += f"Failure: {stats['failure']}\n"
        summary += f"Type Unsupported: {stats['type-unsupported']}\n"
    else:
        summary = "No virus is detected and the file is secure."

    return summary

def scan_file(file_path, user_email):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        "accept": "application/json",

        'x-apikey': '27ac8bc4416b703a61164f18929555fb7260940e16623b729792da460407acf7'
    }
    files = {
        'file': (os.path.basename(file_path), open(file_path, 'rb'))
    }
    response = requests.post(url, headers=headers, files=files)
    print(response.text)
    result = response.json()
    analysis_id = result.get('data', {}).get('id')

    if not analysis_id:
        print(f"No analysis ID returned for file {file_path}")
        return False

    # Poll for the analysis report
    # report_url = f"https://www.virustotal.com/api/v3/files/{analysis_id}"
    report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers['accept'] = 'application/json'
    print(report_url)

    while True:
        report_response = requests.get(report_url, headers=headers)
        report_result = report_response.json()
        status = report_result['data']['attributes']['status']
        if status == 'completed':
            break
        elif status == 'queued':
            time.sleep(10) # Wait for 10 seconds
        else:
            print(f"Unexpected status {status} for file {file_path}")
            return False

    # Check if any engine detected malware
    is_infected = any(details['category'] == 'malicious' for engine, details in
                      report_result['data']['attributes']['results'].items())
    summary = summarize_report(report_result)
    # Send the email with the report

    send_email(user_email, 'VirusTotal File Scan Report', summary)

    return not is_infected

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, to_email, text)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
@app.route('/extend_session', methods=['POST'])
def extend_session():
    session.permanent = True  # Extend session permanency
    app.permanent_session_lifetime = timedelta(minutes=30)  # Extend session lifetime
    return 'Session extended successfully', 200

def setup_logger():
    logger = logging.getLogger('user_actions')
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler('user_actions.log')
    formatter = logging.Formatter('%(asctime)s - %(username)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

logger = setup_logger()

def log_action(username, action):
    if 'username' in session:
        extra = {'username': session['username']}
    else:
        extra = {'username': 'Unknown'}
    logger.info(action, extra=extra)



if __name__ == "__main__":
    app.run(debug=True, ssl_context=('localhost+1.pem', 'localhost+1-key.pem'))