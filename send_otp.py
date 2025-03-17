from flask import Flask, request, jsonify
from flask_mail import Mail, Message
import random
import os



app = Flask(__name__)

# Configure Mail Server (Use your email credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

app.config['MAIL_USERNAME'] = os.getenv("EMAIL_USER")
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_PASS")
mail = Mail(app)

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data['email']
    otp = str(random.randint(1000, 9999))  # Generate 4-digit OTP

    msg = Message('Your OTP Code', sender= os.getenv("EMAIL_USER"), recipients=[email])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

    return jsonify({"otp": otp})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
