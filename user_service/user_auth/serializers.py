from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password
from .signals import send_user_password
from decouple import config
import jwt 
import logging

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'moti_id', 'role', 'password', 'temp_password', 'temp_password_expires', 'is_active', 'is_staff', 'date_registered']
        read_only_fields = ['id', 'moti_id', 'username', 'date_registered']
        extra_kwargs = {
            'password': {'write_only': True},
            'temp_password': {'write_only': True},
            'temp_password_expires': {'write_only': True},
        }

    def encode_jwt(self, payload: dict):
        try:
            secret_hasher = config('PASS_HASHER_SECRET')
            token = jwt.encode(payload, secret_hasher, algorithm="HS256")
            return token

        except Exception as e:
            logger.error(f"JWT encoding error: {e}")
            raise serializers.ValidationError("Failed to generate token")

    def decode_jwt(self, token: str):
        try:
            secret_hasher = config('PASS_HASHER_SECRET')
            decoded_token = jwt.decode(token, secret_hasher, algorithms=["HS256"])
            return decoded_token
            
        except Exception as e:
            logger.error(f"JWT decoding error: {e}")
            raise serializers.ValidationError("Invalid token")

    def validate_email(self, value):
        if not value.endswith("@gmail.com"): 
            raise serializers.ValidationError("Only @gmail.com emails are allowed.")
        return value

    def validate_role(self, value):
        if len(value) < 4:
            raise serializers.ValidationError("Role must be at least 4 characters long.")
        return value

    def create(self, validated_data):
        raw_password = validated_data.pop('password', None)
        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=raw_password,
            **validated_data
        )

        try:
            send_user_password(user, raw_password)
        except Exception as e:
            logger.error(f"Failed to send user password: {e}")

        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        if password:
            instance.set_password(password)
            
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        instance.save()
        return instance