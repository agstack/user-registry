import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

MAIL_USER = os.getenv("APP_MAIL_USERNAME")
MAIL_PASS = os.getenv("APP_MAIL_PASSWORD")

def send_test_email(to_email: str):
    try:
        # Setup email content
        msg = MIMEMultipart()
        msg['From'] = MAIL_USER
        msg['To'] = to_email
        msg['Subject'] = "Test Email - User Registry Configs"

        body = "Hello,\n\nThis is a test email sent using your User Registry email configuration.\n\nCheers!"
        msg.attach(MIMEText(body, 'plain'))

        # Gmail SMTP server
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Connect to server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(MAIL_USER, MAIL_PASS)

        # Send email
        server.send_message(msg)
        server.quit()

        print(f"✅ Test email sent successfully to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


if __name__ == "__main__":
    # Change this to your test email
    test_recipient = "lucky.rnaura@gmail.com"
    send_test_email(test_recipient)
