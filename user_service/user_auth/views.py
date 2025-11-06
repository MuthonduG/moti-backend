from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from .models import User, OtpToken
from .serializers import UserSerializer 
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.mail import send_mail
from .signals import create_token, send_user_password
from datetime import timedelta
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
import geocoder
import logging

logger = logging.getLogger(__name__)

# Get all users
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def getUsers(request):  
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)

    return Response(
        {
            "message": "Fetch successful!",
            "users": serializer.data 
        }, status=status.HTTP_200_OK
    )

# Get authenticated user
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getUser(request): 
    user = request.user

    user_data = {
        "user_email": user.email,
        "user_name": user.username,
        "moti_id": user.moti_id,
        "user_role": user.role,
    }

    return Response(
        {
            "message": "Fetch successful!",
            "user": user_data
        }, status=status.HTTP_200_OK
    )
    
# Register new user
@api_view(['POST'])
@permission_classes([AllowAny])  
def registerUser(request):  
    email = request.data.get('email', '').strip()
    
    if not email:
        return Response(
            { "error": "Email is required!" },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if User.objects.filter(email=email).exists():
        return Response(
            { "error": "Email exists!" },
            status=status.HTTP_409_CONFLICT
        )
    
    # Generate and hash password
    generated_pass = User.generate_password()
    hashed_password = make_password(generated_pass)

    user_data = request.data.copy()
    user_data['password'] = hashed_password
    user_data['temp_password'] = hashed_password
    user_data['temp_password_expires'] = timezone.now() + timedelta(hours=2)

    serializer = UserSerializer(data=user_data)

    if serializer.is_valid():
        user = serializer.save()
        user.is_active = False
        user.save()

        try:
            create_token(user)
        except Exception as e:
            logger.error(f"Failed to send OTP to new user {user.email}: {e}")
            return Response(  
                {"error": f"Failed to send OTP to new user {user.email}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        return Response(
            { 
                "message": "User registered successfully. Please check your email for OTP.",
                "user": serializer.data 
            },
            status=status.HTTP_201_CREATED
        )

    else:
        return Response(
            {"errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )


# login existing user
@api_view(["POST"])
@permission_classes([AllowAny])
def loginUser(request):  
    email = request.data.get('email', '').strip()
    password = request.data.get('password') 

    if not email or not password:
        return Response(
            {"error": "Email and password required!"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)

        if user.check_password(password):
            if not user.is_active:
                return Response(
                    {"error": "Account is inactive!"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Generate JWT token
            payload = {
                'user_id': user.moti_id,
                'exp': timezone.now() + timedelta(days=1),
                'iat': timezone.now()
            }

            token = UserSerializer().encode_jwt(payload=payload)  

            # Get IP address
            user_ip = request.META.get('HTTP_X_FORWARDED_FOR')
            if user_ip:
                user_ip_address = user_ip.split(',')[0]
            else:
                user_ip_address = request.META.get('REMOTE_ADDR')

            # Get location data
            try:
                io_info = geocoder.ip(user_ip_address)
                user.last_login_ipa = [str(ip_info.ip), str(ip_info.city), str(ip_info.country)]
            except Exception as e:
                logger.error(f"Failed to get IP info: {e}")
                user.last_login_ipa = [user_ip_address]
            
            user.save()

            user_data = {
                "user_email": user.email,
                "moti_id": user.moti_id,
                "role": user.role,
                "last_login_ipa": user.last_login_ipa
            }

            return Response(
                {
                    "message": "Login Successful!",
                    "user": user_data,
                    "token": token
                }, status=status.HTTP_200_OK  
            )

        else:
            return Response(
                {"error": "Invalid credentials!"},
                status=status.HTTP_400_BAD_REQUEST
            )
            

    except User.DoesNotExist:
        return Response(
            {"error": "User doesn't exist"},
            status=status.HTTP_400_BAD_REQUEST
        )

# delete user
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def deleteUser(request):  
    user = request.user
    user.delete()
    return Response(
        {"message": "User account successfully deleted!"},
        status=status.HTTP_204_NO_CONTENT
    )