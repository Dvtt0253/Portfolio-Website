from flask import Flask, request, render_template, redirect, url_for,flash
import os
import dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets



app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
sender_email = os.getenv('EMAIL')
email_password = os.getenv('EMAIL_PASSWORD')




@app.route('/portfolio_homepage')
def portfolio_homepage():
    return render_template('homepage.html')


@app.route('/')
def go_to_homepage():
    return redirect(url_for('portfolio_homepage'))



@app.route('/aboutme')
def about_me():
    return render_template('aboutme.html')


@app.route('/skills')
def skills():
    return render_template('skills.html')

@app.route('/Projects')
def projects():
    return render_template('projects.html')


@app.route('/contact/info')
def contact():
    return render_template('contact.html')



@app.route('/send_message', methods=[ 'POST'])
def send_message():
    if request.method == 'POST':

        first_name = request.form['first-name']
        last_name = request.form['last-name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
   

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