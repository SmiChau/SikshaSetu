from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser, OTP


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Admin interface for CustomUser model.
    """
    list_display = ['email', 'role', 'is_verified', 'is_active', 'is_staff', 'date_joined']
    list_filter = ['role', 'is_verified', 'is_active', 'is_staff', 'date_joined']
    search_fields = ['email']
    ordering = ['-date_joined']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('role',)}),
        ('Permissions', {
            'fields': ('is_verified', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role', 'is_verified', 'is_active', 'is_staff'),
        }),
    )
    
    readonly_fields = ['date_joined', 'updated_at', 'last_login']


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    """
    Admin interface for OTP model.
    """
    list_display = ['email', 'otp_code', 'is_used', 'created_at', 'expires_at', 'is_expired']
    list_filter = ['is_used', 'created_at', 'expires_at']
    search_fields = ['email', 'otp_code']
    readonly_fields = ['email', 'otp_code', 'created_at', 'expires_at', 'is_expired']
    ordering = ['-created_at']
    
    def is_expired(self, obj):
        """Display if OTP is expired."""
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'
    
    def has_add_permission(self, request):
        """Prevent manual creation of OTPs from admin."""
        return False
