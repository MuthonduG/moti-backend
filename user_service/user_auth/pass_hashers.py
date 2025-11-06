from django.contrib.auth.hashers import Argon2PasswordHasher
from django.contrib.auth.hashers import PBKDF2PasswordHasher

class CustomArgon2PasswordHasher(Argon2PasswordHasher):
    time_cost = 1000  
    memory_cost = 102400  
    parallelism = 8

class CustomPBKDF2PasswordHasher(PBKDF2PasswordHasher):
    iterations = 100000