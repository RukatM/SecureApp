from django.db import models
from django.contrib.auth.models import AbstractUser



class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    encrypted_totp_key = models.BinaryField(blank=True, null=True)
    totp_key = models.CharField(max_length=64, blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    reset_token = models.CharField(max_length=64, blank=True, null=True)  
    reset_token_expiry = models.DateTimeField(blank=True, null=True)  

    USERNAME_FIELD = 'email'  
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

class Message(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    content = models.TextField()
    signature = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    