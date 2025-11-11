from django.urls import path
from .views import (
    getUsers,
    getUser,
    registerUser,
    loginUser,
    deleteUser,
    verifyUserEmail,
    resendOtp
)

urlpatterns = [
    path('get_users/', getUsers),
    path('get_user/', getUser),
    path('register/', registerUser),
    path('login/', loginUser),
    path('delete_user/', deleteUser),
    path('verify_email/', verifyUserEmail),
    path('resend_otp/', resendOtp),
]
