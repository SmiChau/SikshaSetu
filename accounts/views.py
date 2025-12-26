from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import random
import string

from .models import CustomUser, OTP
from .forms import SignupForm, OTPVerificationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm


def generate_otp():
    """Generate a random 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp_code):
    """
    Send OTP code to user's email for email verification.
    """
    subject = 'Siksha Setu - Email Verification OTP'
    message = f'''
Hello,

Thank you for signing up with Siksha Setu!

Your OTP for email verification is: {otp_code}

This OTP will expire in 10 minutes.

If you did not create an account with Siksha Setu, please ignore this email.

Best regards,
Siksha Setu Team
'''
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def send_password_reset_otp_email(email, otp_code):
    """
    Send OTP code to user's email for password reset.
    """
    subject = 'Siksha Setu - Password Reset OTP'
    message = f'''
Hello,

You have requested to reset your password for your Siksha Setu account.

Your OTP for password reset is: {otp_code}

This OTP will expire in 10 minutes.

If you did not request a password reset, please ignore this email and your password will remain unchanged.

Best regards,
Siksha Setu Team
'''
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def signup_view(request):
    """
    Handle user signup with OTP generation and email sending.
    Stores user data in session until verification is complete.
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            # Store user data in session instead of saving to DB
            # This prevents ghost accounts if verification fails
            request.session['signup_data'] = form.cleaned_data
            
            # Generate OTP
            otp_code = generate_otp()
            request.session['signup_otp'] = otp_code
            
            # Set session expiry (10 minutes)
            request.session.set_expiry(600)
            
            # Send OTP email
            email = form.cleaned_data['email']
            email_sent = send_otp_email(email, otp_code)
            
            if email_sent:
                messages.success(
                    request,
                    f'Account details accepted! An OTP has been sent to {email}. '
                    'Please verify your email to complete registration.'
                )
                return redirect('accounts:verify_otp')
            else:
                messages.error(
                    request,
                    'Failed to send OTP email. Please check your email address or internet connection.'
                )
    else:
        form = SignupForm()
    
    return render(request, 'accounts/auth.html', {'form': form, 'mode': 'signup', 'login_form': LoginForm()})


def verify_otp_view(request):
    """
    Handle OTP verification and create user account.
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    # Check if session has signup data
    signup_data = request.session.get('signup_data')
    session_otp = request.session.get('signup_otp')
    
    if not signup_data or not session_otp:
        messages.error(request, 'Session experienced or invalid. Please sign up again.')
        return redirect('accounts:signup')
        
    email = signup_data.get('email')
    
    if request.method == 'POST':
        otp_input = request.POST.get('otp')
        
        if otp_input == session_otp:
            # Create user now
            try:
                # Double check uniqueness before creation (race condition check)
                if CustomUser.objects.filter(email=email).exists():
                     messages.error(request, 'User with this email already exists.')
                     return redirect('accounts:signup')

                user = CustomUser.objects.create_user(
                    email=email,
                    password=signup_data['password'],
                    # Defaults: is_active=True (since we verify now), is_verified=True
                )
                user.is_verified = True
                user.is_active = True
                user.role = 'student' # Default role, if not in form
                user.save()
                
                # Clear session data
                del request.session['signup_data']
                del request.session['signup_otp']
                
                # Login the user
                login(request, user)
                
                messages.success(
                    request,
                    'Email verified successfully! Your account has been created.'
                )
                return redirect('home')
            except Exception as e:
                messages.error(request, f'Error creating account: {e}')
                print(f"Signup Error: {e}")
        else:
            messages.error(request, 'Invalid OTP. Please check and try again.')
    
    # We pass the email to template to display it
    return render(request, 'accounts/verify_otp.html', {'email': email})


def resend_otp_view(request):
    """
    Resend OTP to user's email using session data.
    """
    if request.method == 'POST':
        signup_data = request.session.get('signup_data')
        
        if not signup_data:
            messages.error(request, 'Session expired. Please sign up again.')
            return redirect('accounts:signup')
        
        email = signup_data.get('email')
        
        # Generate new OTP
        otp_code = generate_otp()
        request.session['signup_otp'] = otp_code
        request.session.set_expiry(600) # Reset expiry
        
        # Send OTP email
        if send_otp_email(email, otp_code):
            messages.success(request, f'New OTP has been sent to {email}.')
        else:
            messages.error(request, 'Failed to send OTP email. Please try again later.')
        
        return redirect('accounts:verify_otp')
    
    return redirect('accounts:verify_otp')


def get_role_redirect_url(user):
    """
    Get redirect URL based on user role.
    
    Args:
        user: CustomUser instance
        
    Returns:
        str: URL name to redirect to
    """
    if user.role == 'student':
        return 'accounts:student_dashboard'
    elif user.role == 'teacher':
        return 'accounts:teacher_dashboard'
    elif user.role == 'admin' or user.is_staff:
        return 'admin:index'
    else:
        return 'home'


def login_view(request):
    """
    Handle user login with email and password.
    Checks if user is verified before allowing login.
    Redirects based on user role after successful login.
    """
    if request.user.is_authenticated:
        # If already logged in, redirect to appropriate dashboard
        return redirect(get_role_redirect_url(request.user))
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            
            # Authenticate user (this will check if user is verified via EmailBackend)
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                # Check if user is verified (double check, though backend already does this)
                if not user.is_verified:
                    messages.error(
                        request,
                        'Your email address has not been verified. Please verify your email before logging in.'
                    )

                    return render(request, 'accounts/auth.html', {'login_form': form, 'mode': 'login', 'form': SignupForm()})
                
                # Check if user is active
                if not user.is_active:
                    messages.error(
                        request,
                        'Your account is currently inactive. Please contact support for assistance.'


                    )
                    return render(request, 'accounts/auth.html', {'login_form': form, 'mode': 'login', 'form': SignupForm()})
                
                # Login the user
                login(request, user)
                
                # Handle Remember Me
                remember_me = form.cleaned_data.get('remember_me')
                if remember_me:
                    # Session expires in 2 weeks (1209600 seconds)
                    request.session.set_expiry(1209600)
                else:
                    # Session expires when browser closes
                    request.session.set_expiry(0)
                
                messages.success(request, f'Welcome back, {user.email}!')
                
                # Redirect to Home page (Requirement: FIRST/HOME page)
                return redirect('home')
            else:
                # Invalid credentials or user not verified
                # Don't reveal specific reason for security
                messages.error(
                    request,
                    'Invalid email or password. Please check your credentials and try again. '
                    'If you have not verified your email, please do so before logging in.'
                )
    else:
        form = LoginForm()
    
    return render(request, 'accounts/auth.html', {'login_form': form, 'mode': 'login', 'form': SignupForm()})


@login_required
def logout_view(request):
    """
    Handle user logout.
    """
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('home')


@login_required
def student_dashboard_view(request):
    """
    Student dashboard page (dummy page for now).
    """
    # Verify user is a student
    if request.user.role != 'student':
        messages.error(request, 'You do not have permission to access this page.')
        return redirect(get_role_redirect_url(request.user))
    
    return render(request, 'accounts/student_dashboard.html', {
        'user': request.user
    })


@login_required
def teacher_dashboard_view(request):
    """
    Teacher dashboard page (dummy page for now).
    """
    # Verify user is a teacher
    if request.user.role != 'teacher':
        messages.error(request, 'You do not have permission to access this page.')
        return redirect(get_role_redirect_url(request.user))
    
    return render(request, 'accounts/teacher_dashboard.html', {
        'user': request.user
    })


def forgot_password_view(request):
    """
    Handle forgot password request - sends OTP to user's email.
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                # Don't reveal if email exists for security
                messages.success(
                    request,
                    'If an account exists with this email, a password reset OTP has been sent.'
                )
                return redirect('accounts:forgot_password')
            
            # Check if user is verified (only verified users can reset password)
            if not user.is_verified:
                messages.error(
                    request,
                    'Your email address has not been verified. Please verify your email first.'
                )
                return render(request, 'accounts/forgot_password.html', {'form': form})
            
            # Generate OTP
            otp_code = generate_otp()
            
            # Mark old password reset OTPs as used (for security)
            OTP.objects.filter(email=email, is_used=False).update(is_used=True)
            
            # Create new OTP record
            otp_obj = OTP.objects.create(
                email=user.email,
                otp_code=otp_code,
                expires_at=timezone.now() + timedelta(minutes=10)
            )
            
            # Send password reset OTP email
            if send_password_reset_otp_email(user.email, otp_code):
                messages.success(
                    request,
                    f'Password reset OTP has been sent to {user.email}. Please check your email.'
                )
                # Redirect to reset password page
                return redirect('accounts:reset_password')
            else:
                messages.error(
                    request,
                    'Failed to send OTP email. Please try again later.'
                )
    else:
        form = ForgotPasswordForm()
    
    return render(request, 'accounts/forgot_password.html', {'form': form})


def reset_password_view(request):
    """
    Handle password reset with OTP verification.
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            otp_code = form.cleaned_data['otp']
            new_password = form.cleaned_data['new_password']
            
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                messages.error(request, 'No account found with this email address.')
                return render(request, 'accounts/reset_password.html', {'form': form})
            
            # Check if user is verified
            if not user.is_verified:
                messages.error(
                    request,
                    'Your email address has not been verified. Please verify your email first.'
                )
                return render(request, 'accounts/reset_password.html', {'form': form})
            
            # Get the most recent valid OTP for this email
            try:
                otp_obj = OTP.objects.filter(
                    email=email,
                    is_used=False
                ).order_by('-created_at').first()
                
                if not otp_obj:
                    messages.error(request, 'No valid OTP found. Please request a new OTP.')
                    return render(request, 'accounts/reset_password.html', {'form': form})
                
                # Check if OTP is expired
                if otp_obj.is_expired():
                    messages.error(request, 'OTP has expired. Please request a new OTP.')
                    return render(request, 'accounts/reset_password.html', {'form': form})
                
                # Verify OTP
                if otp_obj.otp_code == otp_code:
                    # Mark OTP as used
                    otp_obj.is_used = True
                    otp_obj.save()
                    
                    # Reset password (this invalidates old password)
                    user.set_password(new_password)
                    user.save()
                    
                    # Invalidate all user sessions for security
                    sessions = Session.objects.filter(expire_date__gte=timezone.now())
                    for session in sessions:
                        session_data = session.get_decoded()
                        if session_data.get('_auth_user_id') == str(user.id):
                            session.delete()
                    
                    messages.success(
                        request,
                        'Your password has been reset successfully! All your sessions have been logged out. Please login with your new password.'
                    )
                    return redirect('accounts:login')
                else:
                    messages.error(request, 'Invalid OTP. Please check and try again.')
            
            except Exception as e:
                messages.error(request, 'An error occurred during password reset. Please try again.')
                print(f"Error in password reset: {e}")
    else:
        form = ResetPasswordForm()
    
    return render(request, 'accounts/reset_password.html', {'form': form})


def resend_password_reset_otp_view(request):
    """
    Resend password reset OTP to user's email.
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        
        if not email:
            messages.error(request, 'Email address is required.')
            return redirect('accounts:reset_password')
        
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email address.')
            return redirect('accounts:reset_password')
        
        # Check if user is verified
        if not user.is_verified:
            messages.error(
                request,
                'Your email address has not been verified. Please verify your email first.'
            )
            return redirect('accounts:reset_password')
        
        # Generate new OTP
        otp_code = generate_otp()
        
        # Mark old OTPs as used (for security)
        OTP.objects.filter(email=email, is_used=False).update(is_used=True)
        
        # Create new OTP record
        otp_obj = OTP.objects.create(
            email=user.email,
            otp_code=otp_code,
            expires_at=timezone.now() + timedelta(minutes=10)
        )
        
        # Send password reset OTP email
        if send_password_reset_otp_email(user.email, otp_code):
            messages.success(request, f'New password reset OTP has been sent to {user.email}.')
        else:
            messages.error(request, 'Failed to send OTP email. Please try again later.')
        
        return redirect('accounts:reset_password')
    
    return redirect('accounts:reset_password')
