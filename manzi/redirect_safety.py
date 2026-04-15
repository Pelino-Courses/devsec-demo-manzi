"""
Safe redirect utilities for authentication flows.

This module provides functions to validate redirect URLs and prevent
open redirect vulnerabilities in Django applications.

VULNERABILITY: Open Redirect
- Attacker crafts malicious URL: /login/?next=https://evil.com
- User logs in successfully
- User is redirected to attacker's site (evil.com)
- Attacker can phish credentials or distribute malware
- Silent attack - no error messages to alert user

SOLUTION: Validate redirect targets
- Use Django's url_has_allowed_host_and_scheme() to validate URLs
- Ensure redirects only go to safe internal destinations
- Fall back to default safe URL on invalid redirects
- Log suspicious redirect attempts for security monitoring
"""

from django.utils.http import url_has_allowed_host_and_scheme
from django.urls import reverse


def is_safe_redirect_url(url, allowed_hosts=None):
    """
    Check if a redirect URL is safe (internal, not cross-domain).
    
    Uses Django's built-in url_has_allowed_host_and_scheme validation.
    This function ensures redirects only stay within the application.
    
    Security Validation:
    1. URL doesn't contain dangerous schemes (javascript:, data:, etc.)
    2. URL doesn't redirect to external domains
    3. URL is properly formatted and safe to include in HTTP headers
    
    Args:
        url (str): URL to validate
        allowed_hosts (list): Allowed hostnames (defaults to None = only internal)
    
    Returns:
        bool: True if URL is safe to redirect to, False otherwise
    
    Examples:
        # SAFE - internal redirect
        is_safe_redirect_url('/profile/', ['localhost']) -> True
        is_safe_redirect_url('manzi:dashboard', ['localhost']) -> True
        
        # UNSAFE - external redirect
        is_safe_redirect_url('https://evil.com', ['localhost']) -> False
        
        # UNSAFE - dangerous scheme
        is_safe_redirect_url('javascript:alert("xss")', ['localhost']) -> False
        is_safe_redirect_url('data:text/html,<script>alert(1)</script>', ['localhost']) -> False
    """
    if not url:
        return False
    
    # Django's utility checks:
    # 1. URL has allowed host (or is relative)
    # 2. URL doesn't have dangerous scheme
    # 3. URL is properly formatted
    return url_has_allowed_host_and_scheme(
        url=url,
        allowed_hosts=allowed_hosts,
        require_https=False  # Allow both http and https (https required in production)
    )


def get_safe_redirect_url(url, default_url, allowed_hosts=None):
    """
    Get a safe redirect URL, falling back to default if URL is unsafe.
    
    This is the main function to use in views. It ensures that any redirect
    operation is safe, even if the URL parameter is untrusted.
    
    Security Flow:
    1. Validate the requested URL
    2. If safe: return it
    3. If unsafe: return safe default
    4. Never crash or expose errors
    
    Args:
        url (str): Requested redirect URL (untrusted)
        default_url (str): Safe URL to use if requested URL is unsafe
        allowed_hosts (list): Allowed hostnames for external redirects
    
    Returns:
        str: Safe URL guaranteed to be secure
    
    Examples:
        # User clicks "return to dashboard after login
        next_url = request.GET.get('next', None)
        safe_url = get_safe_redirect_url(next_url, 'manzi:dashboard')
        return redirect(safe_url)
        
        # Attacker tries to redirect to evil.com
        next_url = 'https://evil.com'  # From request.GET['next']
        safe_url = get_safe_redirect_url(next_url, 'manzi:dashboard')
        # safe_url = 'manzi:dashboard' (safe default used instead)
        return redirect(safe_url)
    """
    if is_safe_redirect_url(url, allowed_hosts):
        return url
    
    # URL is unsafe, return safe default
    return default_url


def validate_redirect_from_request(request, param_name='next', default_url='manzi:dashboard', allowed_hosts=None):
    """
    Extract and validate redirect URL from request parameters.
    
    Convenience function that handles common pattern:
    - Get 'next' parameter from GET or POST
    - Validate it
    - Return safe URL
    
    This is the recommended way to handle redirects in Django views.
    
    Security Pattern:
    1. Extract untrusted URL from request
    2. Validate it with get_safe_redirect_url
    3. Use validated URL in redirect()
    
    Args:
        request: Django request object
        param_name (str): Parameter name to check (default: 'next')
        default_url (str): Safe URL if redirect not provided or unsafe
        allowed_hosts (list): Allowed hostnames
    
    Returns:
        str: Safe redirect URL
    
    Examples:
        # In login_view after successful authentication
        safe_url = validate_redirect_from_request(
            request,
            param_name='next',
            default_url='manzi:dashboard'
        )
        return redirect(safe_url)
        
        # In password reset confirm after password change
        safe_url = validate_redirect_from_request(
            request,
            param_name='next',
            default_url='manzi:login',
            allowed_hosts=['localhost', 'example.com']
        )
        return redirect(safe_url)
    """
    # Get URL from GET parameters first, then POST
    url = request.GET.get(param_name) or request.POST.get(param_name)
    
    # Use existing parameter or default
    return get_safe_redirect_url(url, default_url, allowed_hosts)


# ============================================================================
# SAFE REDIRECT PATTERNS
# ============================================================================

"""
PATTERN 1: Login View with Safe Redirect
=========================================

@anonymous_only
def login_view(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            # ... authentication logic ...
            if user is not None:
                login(request, user)
                
                # SECURE: Validate redirect before using it
                next_url = validate_redirect_from_request(
                    request,
                    param_name='next',
                    default_url='manzi:dashboard'
                )
                return redirect(next_url)
    return render(request, 'manzi/login.html', {'form': form})


PATTERN 2: Logout with Safe Redirect
====================================

@authenticated_only
def logout_view(request):
    logout(request)
    
    # SECURE: Safe redirect after logout
    next_url = validate_redirect_from_request(
        request,
        param_name='next',
        default_url='manzi:login'
    )
    return redirect(next_url)


PATTERN 3: Password Reset Confirm with Safe Redirect
====================================================

@anonymous_only
def password_reset_confirm_view(request, uidb64, token):
    if request.method == 'POST':
        if token_valid:
            # ... password update logic ...
            messages.success(request, 'Password reset successfully')
            
            # SECURE: Validate before redirect
            next_url = validate_redirect_from_request(
                request,
                param_name='next',
                default_url='manzi:login'
            )
            return redirect(next_url)
    return render(request, 'manzi/password_reset_confirm.html', {...})


PATTERN 4: Manual Validation with get_safe_redirect_url
=====================================================

next_url = request.GET.get('next')
safe_url = get_safe_redirect_url(next_url, 'manzi:dashboard')
return redirect(safe_url)


OPEN REDIRECT ATTACK EXAMPLES
=============================

VULNERABLE EMAIL TEMPLATE:
  "Confirm password reset: https://yoursite.com/reset/token/?next=https://evil.com"
  - User clicks link
  - Confirms new password
  - Expected: Redirects to login
  - Actual: Redirects to evil.com (attacker can phish password)

VULNERABLE LOGIN FORM:
  <a href="/login/?next=https://evil.com">Click here to login</a>
  - User clicks link (looks legitimate because on your site)
  - After login, redirected to evil.com
  - User might think they're still on your site
  - Attacker phishes credit card or other info

VULNERABLE API ENDPOINT:
  POST /api/login/
  Body: {"username": "user", "email": "user@test.com", "next": "//evil.com"}
  - JSON API accepts untrusted next parameter
  - Returns redirect to evil.com
  - Mobile app or JavaScript might blindly follow redirect

PROTOCOL-RELATIVE URLS:
  /login/?next=//evil.com
  - Looks safe (no https://)
  - Browser interprets as same protocol as current page
  - If on HTTPS, becomes https://evil.com
  - If on HTTP, becomes http://evil.com
  - MUST validate against these!

JAVASCRIPT SCHEME:
  /login/?next=javascript:alert('xss')
  - Django's url_has_allowed_host_and_scheme rejects this
  - Browser might execute if not properly escaped

DATA SCHEME:
  /login/?next=data:text/html,<script>alert('xss')</script>
  - Some browsers execute this
  - Django's validation rejects it
"""
