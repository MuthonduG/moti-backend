from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.hashers import make_password, check_password
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.conf import settings
from django.utils.timezone import now
import hashlib
import secrets

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Input cannot be null')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)

        if not password:
            password = User.generate_password()

        user.set_password(password)
        user.save(using=self._db)

        return user, password

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError('Must have staff privileges.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Must have super admin privileges.')

        return self.create_user(email, password, **extra_fields)[0]

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=256, unique=True)
    username = models.CharField(max_length=256, unique=True, editable=True)
    moti_id = models.CharField(max_length=256, editable=False)
    role=models.CharField(max_length=6, MinLengthValidator=4)
    temp_password = models.CharField(max_length=128, blank=True, null=True)
    temp_password_expires = models.DateTimeField(blank=True, null=True)
    last_login_ipa = models.CharField(max_length=256)
    last_login = models.DateTimeField(auto_now_add=True, editable=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_registered = models.DateTimeField(auto_now_add=True, editable=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)
        if self.pk and User.objects.filter(email=self.email).exclude(pk=self.pk).exists():
            raise ValidationError({'email': 'This email is linked to an existing account.'})

    def generate_moti_id(self):
        combined_string = f"{self.id}:{self.email}"
        hashed_string = hashlib.sha256(combined_string.encode("utf-8")).hexdigest()
        compresed_hashed_string = []
        n = 1

        for i in range(1, len(hashed_string)):
            if hashed_string[i] == hashed_string[i-1]:
                n += 1
            else:
                compresed_hashed_string.append(hashed_string[i-1] + str(n))
                n = 1

        compresed_hashed_string.append(hashed_string[i-1] + str(n))
        self.moti_id = ''.join(compresed_hashed_string)
        return self.moti_id

    def has_changed(self, fields):
        if not self.pk:
            return True 
        old_instance = User.objects.filter(pk=self.pk).first()
        return any(getattr(self, field) != getattr(old_instance, field) for field in fields)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def generate_username(self):
        user_email = self.email
        username = user_email.split('@')[0]
        return username

    @staticmethod
    def generate_password():
        return secrets.token_hex(8)

@receiver(pre_save, sender=User)
def pre_save_user(sender, instance, **kwargs):
    if not instance.moti_id or instance.has_changed(['email']):
        instance.moti_id = instance.generate_moti_id()

    if not instance.username or instance.has_changed(['email']):
        instance.username = instance.generate_username()

def generate_otp_code():
    return secrets.token_hex(3).upper()

class OtpToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=6, default=generate_otp_code)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.email

    def is_valid(self):
        return self.otp_expires_at and self.otp_expires_at > now()
    