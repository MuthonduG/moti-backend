from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password
from .signals import send_user_password
from argon2 import PasswordHasher
from decouple import config
import jwt 

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'moti_id', 'password', 'temp_password', 'temp_password_expires', 'is_active', 'is_staff', 'date_registered']
        extra_kwargs = {
            'password': {'write_only': True},
            'temp_password': {'write_only': True},
            'temp_password_expires': {'write_only': True},
        }

    def encode_jwt(self, payload: dict):
        secret_hasher = config('PASS_HASHER_SECRET')
        token = jwt.encode(payload, secret_hasher, algorithm="HS256")
        return token
        

    def decode_jwt(self, token:str):
        secret_hasher = config('PASS_HASHER_SECRET')
        decoded_token = jwt.decode(token, secret_hasher, algorithms=["HS256"])
        return decoded_token

    def validate_email(self, value):
        if not value.endswith("@gmail.com"): 
            raise serializers.ValidationError("Only @gmail.com emails are allowed.")
        return value

    def create(self, validated_data):
        raw_password = validated_data.pop('password', None)
        user = super().create(validated_data)

        if raw_password:
            user.password = make_password(raw_password)
            user.save()

        send_user_password(user, raw_password)

        return user

    def update(self, instance, validated_data):
        password = validated_data.get('password')

        if password:
            validated_data['password'] = make_password(password)
            
        return super().update(instance, validated_data)