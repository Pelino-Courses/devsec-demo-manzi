"""
Brute-force protection utilities for login security.

This module provides functions to track and prevent brute-force attacks on the login system.
It implements a hybrid approach combining account-based and IP-based throttling.

Strategy:
- Track failed attempts by USERNAME and IP ADDRESS
- Implement progressive cooldowns (exponential backoff)
- Temporary account lockout after threshold failures
- Automatic cleanup of old attempts
"""

from django.utils import timezone
from datetime import timedelta
from .models import LoginAttempt


# Configuration Constants
BRUTE_FORCE_CONFIG = {
    # Maximum failed attempts before slowdown
    'FAILED_ATTEMPTS_THRESHOLD': 3,
    
    # Maximum failed attempts before account lockout
    'LOCKOUT_THRESHOLD': 5,
    
    # Base cooldown period (seconds) between attempts
    'BASE_COOLDOWN_SECONDS': 2,
    
    # Account lockout duration (seconds)
    'LOCKOUT_DURATION_SECONDS': 300,  # 5 minutes
    
    # Window to check attempts (minutes)
    'ATTEMPT_WINDOW_MINUTES': 15,
    
    # Cleanup: delete attempts older than this (days)
    'CLEANUP_AFTER_DAYS': 30,
}


class LoginThrottleException(Exception):
    """Raised when login attempt is throttled."""
    pass


def get_client_ip(request):
    """
    Extract client IP address from request.
    
    Handles X-Forwarded-For header for proxied requests,
    falls back to REMOTE_ADDR.
    
    Args:
        request: Django HTTP request
        
    Returns:
        str: Client IP address
    """
    # Check for X-Forwarded-For (from proxies)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP if multiple are present
        ip = x_forwarded_for.split(',')[0].strip()
        return ip
    
    # Fall back to REMOTE_ADDR
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def get_user_agent(request):
    """Extract user-agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')[:500]


def get_recent_failed_attempts(username, ip_address=None, minutes=None):
    """
    Get recent failed login attempts.
    
    Args:
        username: Username to check failed attempts for
        ip_address: Optional IP address to filter by
        minutes: Time window in minutes (uses config default if None)
        
    Returns:
        QuerySet: Recent failed login attempts
    """
    if minutes is None:
        minutes = BRUTE_FORCE_CONFIG['ATTEMPT_WINDOW_MINUTES']
    
    cutoff_time = timezone.now() - timedelta(minutes=minutes)
    
    query = LoginAttempt.objects.filter(
        username=username,
        attempt_type='failed',
        timestamp__gte=cutoff_time
    )
    
    if ip_address:
        query = query.filter(ip_address=ip_address)
    
    return query


def calculate_cooldown_seconds(failed_attempt_count):
    """
    Calculate progressive cooldown based on failure count.
    
    Uses exponential backoff: 2s, 4s, 8s, 16s, 32s...
    Caps at max reasonable value to prevent excessive delays.
    
    Args:
        failed_attempt_count: Number of failed attempts
        
    Returns:
        int: Cooldown period in seconds
    """
    base_cooldown = BRUTE_FORCE_CONFIG['BASE_COOLDOWN_SECONDS']
    
    # Exponential backoff: 2^(attempts-1) * base
    # After 3 attempts: 2^2 * 2 = 8 seconds
    # After 4 attempts: 2^3 * 2 = 16 seconds
    # After 5 attempts: 2^4 * 2 = 32 seconds
    cooldown = base_cooldown * (2 ** max(0, failed_attempt_count - 1))
    
    # Cap at 1 hour maximum
    return min(cooldown, 3600)


def record_login_attempt(username, ip_address, request, success=False):
    """
    Record a login attempt in the database.
    
    Args:
        username: Username attempted
        ip_address: Client IP address
        request: Django HTTP request
        success: Whether attempt was successful
        
    Returns:
        LoginAttempt: Created attempt record
    """
    attempt_type = 'success' if success else 'failed'
    
    attempt = LoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        attempt_type=attempt_type,
        user_agent=get_user_agent(request),
    )
    
    # Clean up old attempts if this is a failed attempt
    if not success:
        cleanup_old_attempts()
    
    return attempt


def is_login_throttled(username, ip_address):
    """
    Check if login attempt should be throttled.
    
    Implements hybrid account + IP based throttling:
    1. Check failed attempts by username (account-based)
    2. Check failed attempts by IP (IP-based)
    3. If either shows excessive failures, throttle
    
    Args:
        username: Username being attempted
        ip_address: Client IP address
        
    Returns:
        tuple: (is_throttled: bool, reason: str, cooldown_seconds: int)
    """
    failed_threshold = BRUTE_FORCE_CONFIG['FAILED_ATTEMPTS_THRESHOLD']
    lockout_threshold = BRUTE_FORCE_CONFIG['LOCKOUT_THRESHOLD']
    
    # Check account-based failures
    user_failures = get_recent_failed_attempts(username).count()
    
    # Check IP-based failures (all usernames from this IP)
    ip_failures = LoginAttempt.objects.filter(
        ip_address=ip_address,
        attempt_type='failed',
        timestamp__gte=timezone.now() - timedelta(
            minutes=BRUTE_FORCE_CONFIG['ATTEMPT_WINDOW_MINUTES']
        )
    ).count()
    
    # Account lockout check (hardlock if too many failures)
    if user_failures >= lockout_threshold:
        cooldown = BRUTE_FORCE_CONFIG['LOCKOUT_DURATION_SECONDS']
        return True, 'Account temporarily locked due to too many failed attempts', cooldown
    
    # Account-based throttling
    if user_failures >= failed_threshold:
        cooldown = calculate_cooldown_seconds(user_failures)
        return True, f'Too many failed attempts. Please try again after {cooldown} seconds.', cooldown
    
    # IP-based throttling (distributed attack detection)
    if ip_failures >= (failed_threshold + 2):  # Slightly higher threshold for IPs
        cooldown = calculate_cooldown_seconds(ip_failures)
        return True, 'Too many login attempts from your IP. Please try again later.', cooldown
    
    return False, '', 0


def get_throttle_wait_time(username, ip_address):
    """
    Get remaining wait time before next login attempt is allowed.
    
    If last failed attempt is within cooldown period, return remaining seconds.
    Otherwise, return 0.
    
    Args:
        username: Username
        ip_address: IP address
        
    Returns:
        int: Seconds to wait, or 0 if no wait needed
    """
    last_attempt = LoginAttempt.objects.filter(
        username=username,
        ip_address=ip_address,
        attempt_type='failed'
    ).order_by('-timestamp').first()
    
    if not last_attempt:
        return 0
    
    # Get number of failures to calculate cooldown
    failures = get_recent_failed_attempts(username, ip_address).count()
    required_cooldown = calculate_cooldown_seconds(failures)
    
    time_since_last = (timezone.now() - last_attempt.timestamp).total_seconds()
    wait_time = max(0, required_cooldown - int(time_since_last))
    
    return wait_time


def clear_login_attempts(username):
    """
    Clear login attempts for a user (called on successful login).
    
    Removes failed attempt records to reset throttling after successful auth.
    
    Args:
        username: Username to clear attempts for
    """
    LoginAttempt.objects.filter(
        username=username,
        attempt_type='failed'
    ).delete()


def cleanup_old_attempts(days=None):
    """
    Delete old login attempt records (maintenance).
    
    Prevents database from growing indefinitely.
    
    Args:
        days: Delete attempts older than this (uses config default if None)
    """
    if days is None:
        days = BRUTE_FORCE_CONFIG['CLEANUP_AFTER_DAYS']
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    deleted_count, _ = LoginAttempt.objects.filter(
        timestamp__lt=cutoff_date
    ).delete()
    
    return deleted_count
