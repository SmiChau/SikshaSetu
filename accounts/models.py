from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
from .managers import CustomUserManager


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model that uses email instead of username for authentication.
    """
    
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('admin', 'Admin'),
    ]
    
    email = models.EmailField(
        unique=True,
        verbose_name='Email Address',
        help_text='Required. Must be a valid email address.'
    )
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='student',
        verbose_name='User Role'
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name='Email Verified',
        help_text='Designates whether the user has verified their email address.'
    )
    is_active = models.BooleanField(
        default=False,
        verbose_name='Active',
        help_text='Designates whether this user should be treated as active. '
                  'Users are inactive until email is verified.'
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name='Staff Status',
        help_text='Designates whether the user can log into the admin site.'
    )
    date_joined = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Date Joined'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Last Updated'
    )
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """Return the email address."""
        return self.email
    
    def get_short_name(self):
        """Return the email address."""
        return self.email


class OTP(models.Model):
    """
    Model to store OTP for email verification.
    """
    email = models.EmailField(
        verbose_name='Email Address',
        db_index=True
    )
    otp_code = models.CharField(
        max_length=6,
        verbose_name='OTP Code'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Created At'
    )
    expires_at = models.DateTimeField(
        verbose_name='Expires At'
    )
    is_used = models.BooleanField(
        default=False,
        verbose_name='Is Used',
        help_text='Designates whether this OTP has been used for verification.'
    )
    
    class Meta:
        verbose_name = 'OTP'
        verbose_name_plural = 'OTPs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'is_used']),
        ]
    
    def __str__(self):
        return f'OTP for {self.email}'
    
    def is_expired(self):
        """Check if OTP has expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()
    
    def save(self, *args, **kwargs):
        """Override save to set expiration time (10 minutes from creation)."""
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)
