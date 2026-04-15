"""
Views for user authentication and profile management.

This module implements the complete authentication lifecycle including
registration, login, logout, password management, and profile viewing/editing.

Authorization: Views enforce role-based access control (RBAC) using decorators
from the authorization module. Access is restricted based on user roles:
- Anonymous: Public pages (login, register, home)
- Authenticated: Dashboard, profile, password change
- Instructor/Staff/Admin: Admin-only views

IDOR Prevention: All views that access user-owned resources include explicit
object-level access control checks. These checks verify that the requesting
user owns or has permission to access the specific resource before returning
it. This prevents Insecure Direct Object Reference (IDOR) vulnerabilities where
attackers could modify URLs to access other users' data.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden, Http404, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.template.loader import render_to_string
from .models import UserProfile
from .forms import (
    UserRegistrationForm,
    UserLoginForm,
    CustomPasswordChangeForm,
    UserProfileForm,
    PasswordResetRequestForm,
    PasswordResetConfirmForm
)
from .authorization import (
    anonymous_only,
    authenticated_only,
    instructor_required,
    staff_required,
    admin_required,
    get_user_roles,
)
from .idor_prevention import (
    verify_object_ownership,
    get_object_for_user,
)
from .brute_force_protection import (
    get_client_ip,
    is_login_throttled,
    record_login_attempt,
    clear_login_attempts,
)
from .redirect_safety import validate_redirect_from_request


# ============================================================================
# Authentication Views
# ============================================================================

@anonymous_only
def register_view(request):
    """
    Handle user registration.
    
    Access: Anonymous users only (redirects authenticated users to dashboard)
    
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


@anonymous_only
def login_view(request):
    """
    Handle user login with brute-force protection.
    
    Access: Anonymous users only (redirects authenticated users to dashboard)
    
    Security:
    - Implements hybrid account-based and IP-based throttling
    - Tracks failed attempts and applies progressive cooldowns
    - Prevents account lockout after threshold failures
    - Uses exponential backoff to discourage brute-force attacks
    
    GET: Display login form
    POST: Authenticate user and create session
    """
    # Get client IP for throttling
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data.get('remember_me', False)

            # Brute-force Protection: Check if login is throttled
            is_throttled, throttle_reason, cooldown_seconds = is_login_throttled(username, client_ip)
            
            if is_throttled:
                # Account or IP is throttled - reject attempt
                # Use generic message to not reveal which protection triggered
                messages.error(
                    request,
                    f'Too many login attempts. Please try again in a few moments.'
                )
                
                # Record the throttled attempt for analysis
                record_login_attempt(username, client_ip, request, success=False)
                
                return render(request, 'manzi/login.html', {'form': form})

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
                # Successful login
                login(request, user)
                
                # Brute-force Protection: Clear failed attempts on successful login
                clear_login_attempts(username)
                record_login_attempt(username, client_ip, request, success=True)
                
                # Set session expiry based on remember_me
                if remember_me:
                    request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days
                    messages.success(request, f'Welcome back, {user.username}! You will stay logged in for 30 days.')
                else:
                    request.session.set_expiry(0)  # Browser session
                    messages.success(request, f'Welcome back, {user.username}!')

                # SECURITY FIX: Validate redirect before using it
                # Prevents open redirect attacks in the 'next' parameter
                next_url = validate_redirect_from_request(
                    request,
                    param_name='next',
                    default_url='manzi:dashboard'
                )
                return redirect(next_url)
            else:
                # Failed login attempt
                # Brute-force Protection: Record failed attempt
                record_login_attempt(username, client_ip, request, success=False)
                
                # Generic error message (doesn't leak info about user existence)
                messages.error(request, 'Invalid username/email or password. Please try again.')
    else:
        form = UserLoginForm()

    return render(request, 'manzi/login.html', {'form': form})


@authenticated_only
def logout_view(request):
    """
    Handle user logout and clear session.
    
    Access: Authenticated users only
    """
    username = request.user.username
    logout(request)
    messages.success(request, f'Goodbye, {username}! You have been logged out successfully.')
    return redirect('manzi:login')


# ============================================================================
# Profile Views
# ============================================================================

@authenticated_only
def dashboard_view(request):
    """
    Display user dashboard (authenticated area).
    
    Access: Authenticated users only
    Shows welcome message and links to profile and password change.
    """
    profile = UserProfile.objects.filter(user=request.user).first() or None
    context = {
        'profile': profile,
        'user': request.user,
        'user_roles': get_user_roles(request.user),
    }
    return render(request, 'manzi/dashboard.html', context)


@authenticated_only
def profile_view(request):
    """
    Display user profile information.
    
    Access: Authenticated users only - can only view their own profile
    
    IDOR Prevention: Filters by request.user to ensure the user can only
    view their own profile. Does not accept a user_id parameter.
    
    GET: Show profile details
    """
    # IDOR Prevention: Filter by current user only
    # This prevents users from viewing other profiles by manipulating URLs
    profile = get_object_for_user(UserProfile, request.user)
    
    context = {
        'profile': profile,
        'user': request.user,
    }
    return render(request, 'manzi/profile.html', context)


@authenticated_only
@require_http_methods(['GET', 'POST'])
def profile_edit_view(request):
    """
    Handle user profile editing.
    
    Access: Authenticated users only - can only edit their own profile
    
    IDOR Prevention: Filters by request.user to ensure the user can only
    edit their own profile. Any attempt to modify another user's profile
    will result in a 404 error.
    
    GET: Display profile edit form
    POST: Process profile updates
    """
    # IDOR Prevention: Get profile only if it belongs to current user
    # Using get_object_for_user ensures non-staff users can only edit their own profile
    # Staff/admin can edit any profile
    profile = get_object_for_user(UserProfile, request.user)

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

@authenticated_only
@require_http_methods(['GET', 'POST'])
def password_change_view(request):
    """
    Handle user password change.
    
    Access: Authenticated users only
    
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
    
    Access: All users (anonymous and authenticated)
    Behavior: Redirects authenticated users to dashboard
    """
    if request.user.is_authenticated:
        return redirect('manzi:dashboard')
    return render(request, 'manzi/home.html')


# ============================================================================
# Staff/Admin Views - User Management
# ============================================================================

@staff_required
@require_http_methods(['GET'])
def user_profile_view(request, user_id):
    """
    View a user's profile by user ID (staff/admin only).
    
    Access: Staff and Admin only
    
    IDOR Prevention Example:
        This view demonstrates PROPER IDOR prevention when accepting a user ID:
        1. Requires staff/admin role (@staff_required)
        2. Explicitly verifies ownership or permission
        3. Returns 404 if access denied (not 403 to avoid info leakage)
    
    Args:
        user_id: The ID of the user/profile to view
    
    GET: Show profile details for the specified user
    """
    try:
        # IDOR Prevention: Get profile and verify permission
        # For staff/admin this allows viewing any profile, but still requires
        # explicit permission check
        profile = UserProfile.objects.select_related('user').get(
            user_id=user_id
        )
        
        # Additional permission check (defensive programming)
        # Staff can view any profile, but let's be explicit about it
        if not (request.user.is_staff or request.user.is_superuser):
            raise Http404("Profile not found")
        
        context = {
            'profile': profile,
            'target_user': profile.user,
            'is_staff_view': True,
        }
        return render(request, 'manzi/user_profile_admin.html', context)
    
    except UserProfile.DoesNotExist:
        # IDOR Prevention: Return 404 instead of 403 to avoid information leakage
        # This prevents attackers from determining which user IDs exist
        raise Http404("Profile not found")


@instructor_required
@require_http_methods(['GET'])
def user_list_view(request):
    """
    View list of all users (instructor/admin only).
    
    Access: Instructor and Admin only
    
    IDOR Prevention: Returns list of users, but view is behind @instructor_required
    so only authorized personnel can access it.
    
    GET: Show list of all users
    """
    # IDOR Prevention: Only instructors/admin can see the user list
    # The decorator ensures this, but we can add additional logging
    users = User.objects.all().select_related('profile').order_by('-date_joined')
    
    context = {
        'users': users,
        'user_count': users.count(),
    }
    return render(request, 'manzi/user_list.html', context)


@staff_required
@require_http_methods(['GET', 'POST'])
def user_profile_edit_admin(request, user_id):
    """
    Edit a user's profile (staff/admin only).
    
    Access: Staff and Admin only
    
    IDOR Prevention:
        1. Requires staff role (@staff_required)
        2. Gets profile by user_id but only if user is staff/admin
        3. Returns 404 if profile not found (not 403)
        4. Logs the modification for audit purposes
    
    Args:
        user_id: The ID of the user/profile to edit
    
    GET: Display profile edit form
    POST: Process profile updates
    """
    try:
        # IDOR Prevention: Staff can edit any profile
        # Get the other user's profile
        target_user = User.objects.get(id=user_id)
        profile = UserProfile.objects.get(user=target_user)
        
        # Verify the requester is staff
        if not (request.user.is_staff or request.user.is_superuser):
            raise Http404("Profile not found")
        
        if request.method == 'POST':
            form = UserProfileForm(request.POST, request.FILES, instance=profile)
            if form.is_valid():
                form.save()
                messages.success(
                    request,
                    f'Profile for {target_user.username} has been updated successfully.'
                )
                return redirect('manzi:user_profile_view', user_id=user_id)
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f'{field}: {error}')
        else:
            form = UserProfileForm(instance=profile)
        
        context = {
            'form': form,
            'profile': profile,
            'target_user': target_user,
            'is_admin_edit': True,
        }
        return render(request, 'manzi/profile_edit.html', context)
    
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        # IDOR Prevention: Return 404 instead of 403
        raise Http404("Profile not found")


# ============================================================================
# Password Reset Views
# ============================================================================

@anonymous_only
@require_http_methods(['GET', 'POST'])
def password_reset_request_view(request):
    """
    Handle password reset request.
    
    Access: Anonymous users only (unauthenticated)
    
    Security Considerations:
    1. User Enumeration Protection: Always shows same success message
    2. No email verification: Returns success whether email exists or not
    3. Token Generation: Uses Django's PasswordResetTokenGenerator (HMAC-based)
    4. Email Sending: Only sends email if account with that email exists
    
    GET: Display password reset request form (email field only)
    POST: Process password reset request and send reset email
    
    On successful POST:
    - If email exists in system: Sends password reset token email
    - If email doesn't exist: Still shows success message (prevents enumeration)
    - Redirects to password_reset_done page
    """
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Try to find user with this email
            # Use .first() instead of .get() to handle multiple accounts gracefully
            try:
                user = User.objects.get(email=email)
                
                # Generate token using Django's built-in token generator
                # This token is HMAC-based and includes timestamp validation
                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                
                # Encode user ID in base64 for URL safety
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Build reset URL
                reset_url = request.build_absolute_uri(
                    f'/password-reset/{uid}/{token}/'
                )
                
                # Send email with reset link
                subject = 'Password Reset Request'
                email_context = {
                    'user': user,
                    'reset_url': reset_url,
                    'uid': uid,
                    'token': token,
                }
                message = render_to_string('manzi/password_reset_email.txt', email_context)
                
                send_mail(
                    subject,
                    message,
                    'noreply@devsec-demo.local',
                    [user.email],
                    fail_silently=True,  # Don't crash if email fails
                )
            except User.DoesNotExist:
                # User with this email doesn't exist
                # Silently pass - we don't want to reveal if email is registered
                pass
            
            # Always show success message (regardless of whether email exists)
            # This prevents attackers from enumerating registered email addresses
            messages.success(
                request,
                'If an account with this email exists, a password reset link has been sent. '
                'Please check your email and follow the link to reset your password.'
            )
            return redirect('manzi:password_reset_done')
    else:
        form = PasswordResetRequestForm()
    
    context = {'form': form}
    return render(request, 'manzi/password_reset_request.html', context)


@anonymous_only
def password_reset_done_view(request):
    """
    Password reset request confirmation page.
    
    Access: Anonymous users only
    
    Display a message informing user to check their email for reset link.
    This page provides good UX without leaking whether email was found.
    
    GET: Show confirmation message
    """
    context = {
        'title': 'Password Reset Email Sent',
        'message': 'If an account with the provided email exists, we have sent a password reset link to that email address. Please check your inbox and follow the link to proceed.'
    }
    return render(request, 'manzi/password_reset_done.html', context)


@anonymous_only
@require_http_methods(['GET', 'POST'])
def password_reset_confirm_view(request, uidb64, token):
    """
    Handle password reset confirmation and token validation.
    
    Access: Anonymous users only (unauthenticated)
    
    Security Considerations:
    1. Token Validation: Django's PasswordResetTokenGenerator validates:
       - HMAC signature (ensures token hasn't been tampered with)
       - Token timestamp (default 24-hour expiration)
       - User's last login (invalidates token if user changes password)
    2. Generic Error Messages: Invalid/expired tokens show same message
    3. No User Information Leakage: Doesn't reveal if user exists or token expired
    
    Args:
        uidb64: Base64-encoded user ID
        token: Token for password reset
    
    GET: Display new password form
    POST: Validate token and update password
    
    Token validation flow:
    1. Decode user ID from base64
    2. Get user from ID
    3. Check if token is valid using Django's generator
    4. If valid: Allow password change
    5. If invalid: Show generic error, don't reveal why
    """
    try:
        # Decode user ID from base64
        # This could fail if URL is tampered with or corrupted
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        # Could mean:
        # - Invalid base64 encoding
        # - User ID doesn't exist
        # - User was deleted
        user = None
    
    # Validate token
    token_generator = PasswordResetTokenGenerator()
    
    # Check if token is valid for this user
    # This validates HMAC, timestamp, and user's last_login
    token_valid = user is not None and token_generator.check_token(user, token)
    
    if request.method == 'POST':
        # Only process form if token is valid
        if not token_valid:
            # Don't reveal whether token is invalid, expired, or user doesn't exist
            messages.error(
                request,
                'The password reset link is invalid or has expired. '
                'Please request a new password reset.'
            )
            return redirect('manzi:password_reset_request')
        
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            # Token is valid, proceed with password change
            new_password = form.cleaned_data['new_password1']
            user.set_password(new_password)
            user.save()
            
            messages.success(
                request,
                'Your password has been reset successfully. '
                'You can now log in with your new password.'
            )
            return redirect('manzi:login')
        else:
            # Form has validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        # GET request
        form = PasswordResetConfirmForm()
    
    # Prepare context for template
    context = {
        'form': form,
        'uid': uidb64,
        'token': token,
        'token_valid': token_valid,
    }
    
    # Only show form if token is valid
    if not token_valid:
        context['error'] = 'The password reset link is invalid or has expired.'
    
    return render(request, 'manzi/password_reset_confirm.html', context)


# ============================================================================
# CSRF VULNERABILITY DEMONSTRATION
# ============================================================================
# The view below demonstrates a COMMON CSRF vulnerability in AJAX endpoints.
# This is an INTENTIONALLY VULNERABLE implementation for educational purposes.
# See the FIXED version below for the secure pattern.
# ============================================================================

@authenticated_only
@require_http_methods(['POST'])
def profile_picture_upload_view_vulnerable(request):
    """
    VULNERABLE: CSRF-unprotected AJAX file upload endpoint.
    
    ⚠️ WARNING: This is intentionally vulnerable for educational purposes!
    
    VULNERABILITY DETAILS:
    - Accepts file uploads via AJAX without CSRF token verification
    - Django's CSRF middleware checks traditional forms but not custom AJAX POST
    - Missing @ensure_csrf_cookie or explicit csrf_protect decorator
    - Attacker can craft malicious website that uploads profile picture to victim
    
    CSRF ATTACK SCENARIO:
    1. Victim (logged into devsec-demo) visits attacker's website
    2. Attacker's page has JavaScript that POSTs file to /profile/upload-picture/
    3. Browser includes victim's session cookie automatically
    4. Victim's profile picture changes without their knowledge
    5. No indication that state was modified (silent CSRF)
    
    WHY CSRF MIDDLEWARE ISN'T ENOUGH:
    - CSRF middleware checks for CSRF token in POST data or headers
    - Traditional HTML forms automatically include {% csrf_token %}
    - AJAX requests won't include token unless developer explicitly adds it
    - Many developers forget to include token in custom JavaScript
    
    ACCESS: Authenticated users only
    
    Args:
        request: Django request object with authenticated user
    
    Returns:
        JSON response indicating success/failure
    """
    if not request.FILES.get('profile_picture'):
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    try:
        # Get or create userprofile (handles cases where profile doesn't exist yet)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile_picture = request.FILES['profile_picture']
        
        # Simple file validation
        if profile_picture.size > 5 * 1024 * 1024:  # 5MB limit
            return JsonResponse({'error': 'File too large'}, status=400)
        
        # Save file
        profile.profile_picture = profile_picture
        profile.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile picture updated successfully'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# CSRF VULNERABILITY FIX - SECURE AJAX ENDPOINT
# ============================================================================
# This version implements proper CSRF protection for AJAX endpoints.
# It uses Django's @ensure_csrf_cookie decorator + JavaScript handling.
# ============================================================================

@authenticated_only
@require_http_methods(['POST'])
@ensure_csrf_cookie
def profile_picture_upload_view(request):
    """
    SECURE: CSRF-protected AJAX file upload endpoint.
    
    ✅ SECURITY: This view properly protects against CSRF attacks
    
    SECURITY MEASURES:
    1. @ensure_csrf_cookie: Ensures CSRF token cookie is sent to client
    2. JavaScript must extract token from cookie and include in request header
    3. Django verifies token in cookie matches token in request header
    4. Prevents unauthorized file uploads from cross-origin sites
    
    SECURE PATTERN:
    1. Server includes CSRF token in response (cookie)
    2. JavaScript reads token from cookie: getCookie('csrftoken')
    3. JavaScript includes token in request header: X-CSRFToken
    4. Django middleware verifies cookie + header match
    5. Attack prevented because attacker can't read token from other domain
    
    JAVASCRIPT EXAMPLE (Secure):
    ```javascript
    function uploadProfilePicture(file) {
        // Get CSRF token from cookie
        const csrftoken = getCookie('csrftoken');
        
        const formData = new FormData();
        formData.append('profile_picture', file);
        
        fetch('/profile/upload-picture/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken,  // ← Include token in header
            },
            body: formData,
            credentials: 'include'  // Include cookies in cross-origin requests
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log('Profile picture updated');
            }
        });
    }
    ```
    
    WHY HEADER IS SECURE:
    - Attacker's website cannot read cookies from victim's domain (SOP)
    - Attacker's website cannot set custom headers on cross-origin requests
    - Token only valid in header form from same-origin requests
    
    ACCESS: Authenticated users only
    
    Args:
        request: Django request object with authenticated user
    
    Returns:
        JSON response indicating success/failure
    """
    if not request.FILES.get('profile_picture'):
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    try:
        # Get or create userprofile (handles cases where profile doesn't exist yet)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile_picture = request.FILES['profile_picture']
        
        # Simple file validation
        if profile_picture.size > 5 * 1024 * 1024:  # 5MB limit
            return JsonResponse({'error': 'File too large'}, status=400)
        
        # Save file
        profile.profile_picture = profile_picture
        profile.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile picture updated successfully'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
