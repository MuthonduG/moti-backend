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

logger = logging.getLogger(__name__)

# Get all users
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def getUsers():
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)

    return Response(
        {
            "message": "Fetch successful!",
            "user": serializer.data
        }, status=status.HTTP_200_OK
    )

# Get authenticated user
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getUser():
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
@permission_classes({AllowAny})
def registerUser(self, request):
    email = request.data.get('email').strip()
    
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
    
    generated_pass = PasswordHasher.encoding(User.generate_password())

    user_data = request.data.copy()
    user_data['password'] = generated_pass
    user_data['temp_password'] = generated_pass
    user_data['temp_password_expires'] = timezone.now() + timedelta(hours=2)

    sanitized_user_data = UserSerializer(data=user_data)

    if sanitized_user_data.is_valid():
        user = sanitized_user_data.save()
        user.is_active = False
        user.set_password(generated_pass)
        user.save()

        try:
            create_token(user)
        except Exception as e:
            Response(
                {"error": f"Failed to send OTP to new user {user.email}: {e}"}
            )
        
        return Response(
            { "user": sanitized_user_data.data },
            status=status.HTTP_201_CREATED
        )

    else:
        return Response(
            {"errors": sanitized_user_data.errors},
            status=status.HTTP_400_BAD_REQUEST
        )


# login existing user
@api_view(["POST"])
@permission_classes([AllowAny])
def loginUser(self, request):
    email = request.data.get('email').strip()

    password = request.date.get('password')

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
            
            payload = {
                'user_id': user.moti_id,
                'exp': timezone.now() + timedelta(days=1),
                'iat': timezone.now()
            }

            token = UserSerializer.encode_jwt(payload=payload)

            user_data = {
                "user_email": user.email,
                "moti_id": user.moti_id,
                "role": user.role
            }

            return Response(
                {
                    "message": "Login Successful!",
                    "user": user_data,
                    "token": token
                }, status=status.HTTP_202_ACCEPTED
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
def deleteUser():
    user = request.user
    user.delete()
    return Response(
        {"message": "User account successfully deleted!"},
        status=status.HTTP_204_NO_CONTENT
    )

# lo