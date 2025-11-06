from django.db.models.signals import post_save
from django.conf import settings
from django.dispatch import receiver
from .models import OtpToken, User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone

def send_otp_email(user, otp_code):
    subject = "Moti Email Verification"
    sender = "muthondugithinji@gmail.com"
    receiver = [user.email]

    email_template = render_to_string("emails/otp_email.html", {
        'user': user,
        'otp_code': otp_code,
        'expiration': '1hr'
    })

    text_content = f"Hi {user.email}, your OTP is {otp_code}. It expires in one hour."
    email = EmailMultiAlternatives(subject, text_content, sender, receiver)
    email.attach_alternative(email_template, "text/html")
    email.send()

def send_user_password(user, password):
    subject = "Welcome to Moti – Your Login Credentials"
    sender = "muthondugithinji@gmail.com"
    receiver = [user.email]

    email_template = render_to_string("emails/pass_email.html", {
        'user': user,
        'password': password, 
    })

    text_content = f"Hi {user.email}, your password is: {password}. Please do not share it with anyone."
    email = EmailMultiAlternatives(subject, text_content, sender, receiver)
    email.attach_alternative(email_template, "text/html")
    email.send()

def create_token(user):
    otp_token = OtpToken.objects.create(
        user=user,
        otp_expires_at=timezone.now() + timezone.timedelta(hours=1)
    )
    send_otp_email(user, otp_token.otp_code)
    return otp_token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def post_save_create_token(sender, instance, created, **kwargs):
    if created and not instance.is_superuser and not instance.is_staff:
        create_token(instance)