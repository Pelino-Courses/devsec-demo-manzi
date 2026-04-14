"""
Views for user authentication and profile management.

This module implements the complete authentication lifecycle including
registration, login, logout, password management, and profile viewing/editing.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden
from .models import UserProfile
from .forms import (
    UserRegistrationForm,
    UserLoginForm,
    CustomPasswordChangeForm,
    UserProfileForm
)


# ============================================================================
# Authentication Views
# ============================================================================

def register_view(request):
    """
    Handle user registration.
    
    GET: Display registration form
    POST: Process registration form and create new user
    """
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Auto-login after registration
            login(request, user)
            messages.success(
                request,
                f'Welcome, {user.username}! Your account has been created successfully.'
            )
            return redirect('manzi:dashboard')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = UserRegistrationForm()

    return render(request, 'manzi/register.html', {'form': form})


def login_view(request):
    """
    Handle user login.
    
    GET: Display login form
    POST: Authenticate user and create session
    """
    if request.user.is_authenticated:
        return redirect('manzi:dashboard')

    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data.get('remember_me', False)

            # Try to authenticate with username first, then email
            user = None
            if '@' in username:
                # Likely an email
                try:
                    user_obj = User.objects.get(email=username)
                    user = authenticate(request, username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            else:
                # Try as username
                user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                
                # Set session expiry based on remember_me
                if remember_me:
                    request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days
                    messages.success(request, f'Welcome back, {user.username}! You will stay logged in for 30 days.')
                else:
                    request.session.set_expiry(0)  # Browser session
                    messages.success(request, f'Welcome back, {user.username}!')

                # Redirect to next page or dashboard
                next_url = request.GET.get('next', 'manzi:dashboard')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid username/email or password. Please try again.')
    else:
        form = UserLoginForm()

    return render(request, 'manzi/login.html', {'form': form})


@login_required(login_url='manzi:login')
def logout_view(request):
    """
    Handle user logout and clear session.
    """
    username = request.user.username
    logout(request)
    messages.success(request, f'Goodbye, {username}! You have been logged out successfully.')
    return redirect('manzi:login')


# ============================================================================
# Profile Views
# ============================================================================

@login_required(login_url='manzi:login')
def dashboard_view(request):
    """
    Display user dashboard (authenticated area).
    
    Shows welcome message and links to profile and password change.
    """
    profile = UserProfile.objects.filter(user=request.user).first() or None
    context = {
        'profile': profile,
        'user': request.user,
    }
    return render(request, 'manzi/dashboard.html', context)


@login_required(login_url='manzi:login')
def profile_view(request):
    """
    Display user profile information.
    
    GET: Show profile details
    """
    profile = get_object_or_404(UserProfile, user=request.user)
    context = {
        'profile': profile,
        'user': request.user,
    }
    return render(request, 'manzi/profile.html', context)


@login_required(login_url='manzi:login')
@require_http_methods(['GET', 'POST'])
def profile_edit_view(request):
    """
    Handle user profile editing.
    
    GET: Display profile edit form
    POST: Process profile updates
    """
    profile = get_object_or_404(UserProfile, user=request.user)

    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('manzi:profile')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = UserProfileForm(instance=profile)

    context = {
        'form': form,
        'profile': profile,
    }
    return render(request, 'manzi/profile_edit.html', context)


# ============================================================================
# Password Management Views
# ============================================================================

@login_required(login_url='manzi:login')
@require_http_methods(['GET', 'POST'])
def password_change_view(request):
    """
    Handle user password change.
    
    GET: Display password change form
    POST: Process password change
    """
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Re-authenticate to prevent session logout
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('manzi:dashboard')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = CustomPasswordChangeForm(request.user)

    context = {'form': form}
    return render(request, 'manzi/password_change.html', context)


# ============================================================================
# Public Views
# ============================================================================

def home_view(request):
    """
    Home page - redirects to dashboard if authenticated, shows info otherwise.
    """
    if request.user.is_authenticated:
        return redirect('manzi:dashboard')
    return render(request, 'manzi/home.html')
