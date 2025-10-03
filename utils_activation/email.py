from flask_mail import Message

from dbms import app, mail


def send_email(to, subject, template):
    """
    Send an email with the activation link
    """
    try:
        msg = Message(
            subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
    except Exception as e:
        return e
