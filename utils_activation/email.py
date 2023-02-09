from flask_mail import Message

from dbms import app, mail


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=["your@email.com"],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
