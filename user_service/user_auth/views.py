from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from .models import User, OtpToken
from .serializers import UserSerializer
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.mail import send_mail
from .signals import create_token, send_user_password, send_account_deletion_confirmation
from datetime import timedelta
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
import geocoder, logging, jwt
from decouple import config
from google.auth.transport import requests
from google.oauth2 import id_token


logger = logging.getLogger(__name__)

# get all users
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


# get authenticated user
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


# implicit register new user
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
    
    generated_pass = User.generate_password()
    hashed_password = make_password(generated_pass)

    user_data = request.data.copy()
    user_data['password'] = hashed_password
    user_data['temp_password'] = generated_pass 
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

        if user.login_count < 1:
            if password == user.temp_password:
                new_user_pass = user.data.get('new_password')

                if not new_user_pass and new_user_pass == user.temp_password:
                    return Resposne(
                        {"error": "You cannot set your use"}
                    )

        if user.check_password(password):
            if not user.is_active:
                return Response(
                    {"error": "Account is inactive!"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            if user.temp_password:
                if user.check_password(password) == user.temp_password:
                    return Response(
                        {"error": f"You passord will expire in {user.temp_password_expires - timezone.now()}"}
                    )
                
                user.temp_password = None

            payload = {
                'user_id': user.moti_id,
                'exp': timezone.now() + timedelta(days=1),
                'iat': timezone.now()
            }

            token = UserSerializer().encode_jwt(payload=payload)  

            user_ip = request.META.get('HTTP_X_FORWARDED_FOR')
            if user_ip:
                user_ip_address = user_ip.split(',')[0]
            else:
                user_ip_address = request.META.get('REMOTE_ADDR')

            try:
                ip_info = geocoder.ip(user_ip_address)  
                user.last_login_ipa = [str(ip_info.ip), str(ip_info.city), str(ip_info.country)]
            except Exception as e:
                logger.error(f"Failed to get IP info: {e}")
                user.last_login_ipa = [user_ip_address]
            
            user.login_count += 1
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


# explicit register and login new user
@api_view(['POST'])
@permission_classes([AllowAny])
def googleOAuth(request):

    try:
        token = request.data.get('token')
        if not token:
            return Response({"error": "Google ID Token required"}, status=status.HTTP_400_BAD_REQUEST)

        info = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            config("GOOGLE_OAUTH_CLIENT_ID")
        )

        if info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
            return Response({"error": "Invalid Google token issuer"}, status=status.HTTP_400_BAD_REQUEST)

        email = info.get("email")
        if not email:
            return Response({"error": "Email missing in token"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()

        if user:
            if user.login_count is None:
                user.login_count = 0

            user.login_count += 1
            user.save()

            payload = {
                "user_id": user.moti_id,
                "email": user.email,
                "exp": timezone.now() + timedelta(days=1),
                "iat": timezone.now()
            }
            token = UserSerializer().encode_jwt(payload=payload)

            return Response({
                "message": "Login successful",
                "user": UserSerializer(user).data,
                "token": token,
                "is_new_user": False
            }, status=status.HTTP_200_OK)

        user = User(
            email=email,
            role="user",
            is_active=True,
            sso_signup=True,
            login_count=1
        )

        user.set_password(User.generate_password())
        user.save() 

        payload = {
            "user_id": user.moti_id,
            "email": user.email,
            "exp": timezone.now() + timedelta(days=1),
            "iat": timezone.now()
        }
        token = UserSerializer().encode_jwt(payload=payload)

        return Response({
            "message": "User registered successfully",
            "user": UserSerializer(user).data,
            "token": token,
            "is_new_user": True
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Google OAuth unexpected error: {e}")
        return Response({"error": "Authentication failed"}, status=status.HTTP_400_BAD_REQUEST)


# delete user
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
async def deleteUser(request):
    try:
        user = request.user
        otp_code = request.data.get('otp_code')
        
        if not otp_code:
            return await request_confirmation(user, send_account_deletion_confirmation)
        
        return await confirm_and_delete_user(user, otp_code)
        
    except Exception as e:
        logger.error(f"Async delete user error: {e}")
        return Response(
            {"error": "Failed to process deletion request"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Send deletion confirmation OTP
async def request_confirmation(user, email_func):
    otp_token = await sync_to_async(create_token(user=user, ))
    
    email_sent = await email_func(user, otp_token)
    
    if email_sent:
        return Response(
            {
                "message": "Request confirmation sent to your email",
                "next_step": "Confirm with OTP code"
            },
            status=status.HTTP_200_OK
        )
    else:
        return Response(
            {"error": "Failed to send confirmation"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Verify OTP and delete user
async def confirm_and_delete_user(user, otp_code):
    is_valid = await verify_otp(user, otp_code)
    
    if not is_valid:
        return Response(
            {"error": "Invalid or expired OTP"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user_email = user.email
    await sync_to_async(user.delete)()
        
    return Response(
        {"message": "Account successfully deleted"},
        status=status.HTTP_200_OK
    )

# Verify deletion OTP
async def verify_otp(user, otp_code):
    try:
        otp_token = await sync_to_async(
            lambda: OtpToken.objects.filter(user=user).latest('otp_created_at')
        )()
        
        if (timezone.now() > otp_token.otp_expires_at or 
            otp_token.otp_code.lower() != otp_code.lower()):
            return False
        
        await sync_to_async(otp_token.delete)()
        return True
        
    except OtpToken.DoesNotExist:
        return False


# verify email
@api_view(['POST'])
@permission_classes([AllowAny])
def verifyUserEmail(request):
    serializer = UserSerializer()

    email = serializer.validate_email(request.data.get('email'))
    otp_code = request.data.get('otp_token')

    if not email or not otp_code:
        return Response(
            {"message": "Email and OTP code are required."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = get_object_or_404(User, email=email)
    user_otp = OtpToken.objects.filter(user=user).last()  

    if not user_otp: 
        return Response(
            {"message": "No OTP found for this user."},
            status=status.HTTP_404_NOT_FOUND
        )   
    
    if timezone.now() > user_otp.otp_expires_at:
        return Response(
            {"message": "The OTP has expired. Please request a new one."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if user_otp.otp_code.lower() != otp_code.lower():
        return Response(
            {"message": "Invalid OTP. Please try again."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user.is_active = True
    user_pass = user.temp_password

    if user.role.lower() == 'admin':
        user.is_staff = True

    if timezone.now() > user.temp_password_expires:
        if user_pass:
            send_user_password(user, user_pass)

        user_pass = User.generate_password()
        user.temp_password = user_pass
        user.temp_password_expires = timezone.now() + timedelta(hours=2)
        send_user_password(user, user_pass)
    
    if user_pass:
        send_user_password(user, user_pass)

    user_otp.delete()
    
    return Response(
        {"message": "Account has been activated successfully! Your password has been sent to your email."},
        status=status.HTTP_200_OK
    )

# resend OTP
@api_view(['POST'])
@permission_classes([AllowAny])
def resendOtp(request):
    email = UserSerializer.validate_email(request.data.get("email"))
    if not email:
        return Response(
            {"message": "Email is required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = get_object_or_404(User, email=email)
    OtpToken.objects.filter(user=user).delete()

    try:
        create_token(user)  
        logger.info(f"Generated and sent new OTP for user {user.email}")
    except Exception as e:
        logger.error(f"Failed to generate/send OTP for {user.email}: {e}")
        return Response(
            {"message": "Failed to send OTP. Please try again later."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return Response(
        {"message": "A new OTP has been sent to your email address."},
        status=status.HTTP_200_OK,
    )

# update password
@api_view(['POST'])
@permission_classes([AllowAny])
async def updatePassword(request):
    try:
        email = UserSerializer.validate_email(request.data.get('email'))
        password = request.data.get('password')
        otp_code = request.data.get('otp_token')
        user = get_object_or_404(email=email)

        user = get_object_or_404(email=email)

        if not otp_code:
            return await request_confirmation(user=user, email_func=send_otp_email)
        
        return confirm_and_update_pass(user, otp_code, password)

    except Exception as e:
        logger.error(f"Async delete user error: {e}")
        return Response(
            {"error": "Failed to process password change request"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    

async def confirm_and_update_pass(user, otp_code, password):
    is_valid = await verify_otp(user=user, otp_code=otp_code)
    
    if not is_valid:
        return Response(
            {"error": "Invalid OTP"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user.password = password
    user.updated_at = timezone.now()

    user.save()

    return Response(
        {"message": "Password updated successfully"},
        status=status.HTTP_202_ACCEPTED
    )

