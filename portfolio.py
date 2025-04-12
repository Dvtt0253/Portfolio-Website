from flask import Flask, request, render_template, redirect, url_for,flash
import os
import dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import flask_firewall





app = Flask(__name__)

firewall = flask_firewall.Firewall(50,60)

app.secret_key = secrets.token_hex(32)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
sender_email = os.getenv('EMAIL')
email_password = os.getenv('EMAIL_PASSWORD')




@app.route('/portfolio_homepage')
def portfolio_homepage():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return render_template('homepage.html')


@app.route('/')
def go_to_homepage():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return redirect(url_for('portfolio_homepage'))



@app.route('/aboutme')
def about_me():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return render_template('aboutme.html')


@app.route('/skills')
def skills():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return render_template('skills.html')

@app.route('/Projects')
def projects():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return render_template('projects.html')


@app.route('/contact/info')
def contact():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    return render_template('contact.html')



@app.route('/send_message', methods=[ 'POST'])
def send_message():
    is_blocked = firewall.block_access()
    if is_blocked == 403:
        return "Denied Access", 403
    if firewall.rate_limiter() == 429:
        return "Too many Requests", 429
    if request.method == 'POST':

        first_name = firewall.santitize_input(request.form['first-name'])
        if firewall.identify_payloads(first_name) == 403:
            return "Malicious Activity Detected. Access permanently denied.", 403
        last_name = firewall.santitize_input(request.form['last-name'])
        if firewall.identify_payloads(last_name) == 403:
            return "Malicious Activity Detected. Access permanently denied.", 403
        email = firewall.santitize_input(request.form['email'])
        if firewall.identify_payloads(email) == 403:
            return "Malicious Activity Detected. Access permanently denied.", 403
        subject = firewall.santitize_input(request.form['subject'])
        if firewall.identify_payloads(subject) == 403:
            return "Malicious Activity Detected. Access permanently denied.", 403
        message = firewall.santitize_input(request.form['message'])
        if firewall.identify_payloads(message) == 403:
            return "Malicious Activity Detected. Access permanently denied.", 403
   

        try:
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = sender_email
            msg['Subject'] = subject
            html_content = render_template('email.html', first_name=first_name, last_name=last_name, email=email, message=message)
            msg.attach(MIMEText(html_content, 'html'))

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(sender_email, email_password)
                server.sendmail(sender_email, sender_email , msg.as_string())
        except Exception as e:
            print(f"Error while sending email {e}")
        flash("Your message has been sent successfully! ", category='success')
        return redirect(url_for('contact'))



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004)