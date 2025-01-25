from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
import datetime
import bcrypt
import os
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB Configuration
uri = "mongodb+srv://whitedevil7628:mohit038@cluster1.oohsn.mongodb.net/myDatabase?retryWrites=true&w=majority"
client = MongoClient(uri)
db = client["endsem"]
users_collection = db["users"]

# Email Configuration
app.config['MAIL_USERNAME'] = 'librarymanagementprjoect@gmail.com'
app.config['MAIL_PASSWORD'] = 'ykqy zkvd zzak ujpa'

# Helper Functions
def send_email(email, subject, body):
    port = 587
    smtp_server = "smtp.gmail.com"
    sender_email = app.config['MAIL_USERNAME']
    password = app.config['MAIL_PASSWORD']

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.login(sender_email, password)
        server.sendmail(sender_email, email, message.as_string())

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({"email": email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user'] = email
            session['role'] = user.get('role', 'employee')  # Set the user's role
            
            # Redirect based on the role (admin or employee)
            if session['role'] == 'admin':
                return redirect(url_for('admin_home'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username=request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # Get role (admin or employee)
        
        # Check if the role is admin and if an admin already exists
        if role == 'admin':
            admin_exists = users_collection.find_one({"role": "admin"})
            if admin_exists:
                flash('An admin already exists. Only one admin is allowed.', 'danger')
                return redirect(url_for('signup')) 
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if users_collection.find_one({"email": email}):
            flash('Email already registered.', 'danger')
        else:
            if role == 'admin' or users_collection.count_documents({}) == 0:
                role = 'admin'
            else:
                role = 'employee'
            otp = generate_otp()
            # role = 'admin' if users_collection.count_documents({}) == 0 else 'employee'
            users_collection.insert_one({
                "username":username,
                "email": email,
                "password": hashed_password,
                "otp": otp,
                "verified": False,
                "role": role
            })
            send_email(email, "Email Verification", f"Your OTP is: {otp}")
            flash('OTP sent to your email.', 'info')
            return redirect(url_for('verify_otp', email=email))
    return render_template('signup.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if request.method == 'POST':
        otp = request.form['otp']
        user = users_collection.find_one({"email": email})

        if user and user['otp'] == otp:
            users_collection.update_one({"email": email}, {"$set": {"verified": True}})
            flash('Email verified successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP.', 'danger')
    return render_template('verify_otp.html', email=email)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({"email": email})

        if user:
            otp = generate_otp()
            users_collection.update_one({"email": email}, {"$set": {"otp": otp}})
            send_email(email, "Password Reset", f"Your OTP for password reset is: {otp}")
            flash('OTP sent to your email.', 'info')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        user = users_collection.find_one({"email": email})

        if user and user['otp'] == otp:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            users_collection.update_one({"email": email}, {"$set": {"password": hashed_password, "otp": None}})
            flash('Password reset successful.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP.', 'danger')
    return render_template('reset_password.html', email=email)


@app.route('/admin_home')
def admin_home():
    if 'user' in session and session.get('role') == 'admin':
        user=users_collection.find_one({"email": session['user']})
        if user:
            username = user['username']
            return render_template('admin_home.html',username=username)
    else:
        flash('Access denied. Only admin can access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user' in session and session.get('role') == 'employee':
        user = users_collection.find_one({"email": session['user']})
        if user:
            username = user['username']
            return render_template('home.html', username=username)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))
    else:
        flash('Access denied. Please log in as an employee.', 'danger')
        return redirect(url_for('login'))



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
