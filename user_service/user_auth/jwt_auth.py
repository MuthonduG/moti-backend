from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone as dj_timezone
from datetime import datetime, timezone
import jwt
from decouple import config
from .models import User
import logging

logger = logging.getLogger(__name__)

class CustomJWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        if not auth_header:
            return None

        try:
            # Extract token from "Bearer <token>"
            token_type, token = auth_header.split(' ')

            if token_type.lower() != 'bearer':
                raise AuthenticationFailed('Invalid token type. Use Bearer token.')

            # Decode token
            secret = config('PASS_HASHER_SECRET')
            payload = jwt.decode(token, secret, algorithms=['HS256'])

            # Check expiration
            exp_timestamp = payload.get('exp')
            if not exp_timestamp:
                raise AuthenticationFailed('Token has no expiration')

            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

            if exp_datetime < dj_timezone.now():
                raise AuthenticationFailed('Token has expired')

            # Identify user
            user_id = payload.get('user_id')
            if not user_id:
                raise AuthenticationFailed('Invalid token payload')

            user = User.objects.get(moti_id=user_id)

            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')
        except ValueError:
            raise AuthenticationFailed('Invalid authorization header format')
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationFailed('Authentication failed')

