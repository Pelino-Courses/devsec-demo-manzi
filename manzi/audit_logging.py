"""
Audit Logging Module

Provides utilities for logging security-relevant events to the AuditLog model.
All logging functions follow these principles:

1. Immutability: Logs are write-once, never modified
2. Security: Never logs passwords, secrets, or sensitive data
3. Privacy: Only captures necessary information
4. Performance: Efficient database writes with indexed queries
5. Debuggability: Structured, queryable data for forensic analysis
"""

import logging
from django.utils import timezone
from django.contrib.auth.models import User
from .models import AuditLog

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Extract client IP address from request.
    
    Handles common proxy scenarios (X-Forwarded-For, X-Real-IP).
    Security Note: This is for audit purposes - if behind a proxy,
    ensure proxy is trusted and correctly configured.
    """
    # Check for X-Forwarded-For header (common in proxies)
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        # Take the first IP (client) if multiple IPs are present
        return forwarded_for.split(',')[0].strip()
    
    # Check for X-Real-IP header
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        return x_real_ip
    
    # Fall back to REMOTE_ADDR (direct connection)
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def get_user_agent(request):
    """Extract user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


def log_audit_event(
    event_type,
    request,
    username=None,
    user=None,
    description="",
    details=None,
    severity="info"
):
    """
    Log a security-relevant event to the audit log.
    
    Args:
        event_type (str): Type of event from AuditLog.EVENT_TYPE_CHOICES
        request (HttpRequest): The Django request object (for IP, user-agent)
        username (str, optional): Username involved in the event
        user (User, optional): Django User object if authenticated
        description (str): Human-readable description of the event
        details (dict, optional): Structured data about the event (never include passwords!)
        severity (str): 'info', 'warning', 'error', or 'critical'
    
    Returns:
        AuditLog: The created audit log entry
    
    Security Guarantees:
    - NEVER logs passwords or credentials
    - NEVER logs secret tokens or API keys
    - NEVER modifies logs after creation
    - Always records IP address and timestamp
    - Always records username for accountability
    
    Example:
        log_audit_event(
            event_type='auth_login_success',
            request=request,
            username='john_doe',
            user=user_obj,
            description='User successfully logged in via password',
            details={'login_method': 'password', 'mfa_used': False},
            severity='info'
        )
    """
    if details is None:
        details = {}
    
    # Ensure no sensitive data in details dict
    forbidden_keys = ['password', 'pwd', 'secret', 'token', 'api_key', 'access_token', 'refresh_token', 'credentials']
    for key in details.keys():
        if any(forbidden in key.lower() for forbidden in forbidden_keys):
            logger.warning(f"Attempted to log sensitive field '{key}' in audit details")
            del details[key]
    
    try:
        audit_log = AuditLog.objects.create(
            event_type=event_type,
            timestamp=timezone.now(),
            severity=severity,
            user=user,
            username=username or (user.username if user else 'anonymous'),
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            description=description,
            details=details
        )
        logger.debug(f"Audit log created: {audit_log}")
        return audit_log
    except Exception as e:
        logger.error(f"Failed to create audit log: {str(e)}", exc_info=True)
        # Don't raise - logging failures shouldn't break application


def log_registration(request, username, user=None):
    """
    Log user registration event.
    
    Args:
        request: HTTP request object
        username: Username of newly registered user
        user: User object (if available at logging time)
    """
    log_audit_event(
        event_type='auth_registration',
        request=request,
        username=username,
        user=user,
        description=f"User account '{username}' registered successfully",
        details={'action': 'registration', 'email_verified': False},
        severity='info'
    )


def log_login_success(request, username, user=None, mfa_used=False):
    """
    Log successful login event.
    
    Args:
        request: HTTP request object
        username: Username of authenticated user
        user: User object
        mfa_used: Whether multi-factor authentication was used
    
    Security Note: Do NOT include passwords here
    """
    log_audit_event(
        event_type='auth_login_success',
        request=request,
        username=username,
        user=user,
        description=f"User '{username}' logged in successfully",
        details={
            'login_method': 'username_password',
            'mfa_used': mfa_used,
            'session_start': timezone.now().isoformat()
        },
        severity='info'
    )


def log_login_failure(request, username, reason="Invalid credentials", throttled=False):
    """
    Log failed login attempt.
    
    Args:
        request: HTTP request object
        username: Username attempted
        reason: Why login failed (e.g., "Invalid credentials", "Account locked")
        throttled: Whether request was throttled/rate-limited
    
    Security Note: Log enough detail for forensics without exposing the reason too specifically
    """
    log_audit_event(
        event_type='auth_login_failure',
        request=request,
        username=username,
        description=f"Failed login attempt for user '{username}'",
        details={
            'failure_reason': reason,
            'throttled': throttled,
            'attempt_timestamp': timezone.now().isoformat()
        },
        severity='warning' if not throttled else 'error'
    )


def log_logout(request, username, user=None):
    """Log user logout event."""
    log_audit_event(
        event_type='auth_logout',
        request=request,
        username=username,
        user=user,
        description=f"User '{username}' logged out",
        details={'action': 'logout'},
        severity='info'
    )


def log_password_change(request, username, user=None, method='web'):
    """
    Log password change event.
    
    Args:
        request: HTTP request object
        username: Username whose password changed
        user: User object
        method: How password was changed ('web', 'admin', 'api', etc.)
    
    Security Note:
    - Log the EVENT, not the password
    - Log WHO changed it and HOW, not the value or hash
    - This enables detection of compromised accounts changing their own password
    """
    log_audit_event(
        event_type='auth_password_change',
        request=request,
        username=username,
        user=user,
        description=f"Password changed for user '{username}'",
        details={
            'change_method': method,
            'changed_at': timezone.now().isoformat(),
            'ip_address_at_change': get_client_ip(request)
        },
        severity='info'
    )


def log_password_reset_request(request, username):
    """
    Log password reset request.
    
    Args:
        request: HTTP request object
        username: Username requesting reset
    
    Security Note: Log the REQUEST, not the reset token or link
    """
    log_audit_event(
        event_type='auth_password_reset_request',
        request=request,
        username=username,
        description=f"Password reset requested for user '{username}'",
        details={'reset_requested_at': timezone.now().isoformat()},
        severity='info'
    )


def log_password_reset_confirm(request, username, user=None, success=True):
    """
    Log password reset confirmation (actual password change via reset).
    
    Args:
        request: HTTP request object
        username: Username
        user: User object
        success: Whether reset was successful
    
    Security Note:
    - Log who performed password reset
    - Log IP address (detect if reset from unusual location)
    - Never log the reset token or temporary credentials
    """
    log_audit_event(
        event_type='auth_password_reset_confirm',
        request=request,
        username=username,
        user=user,
        description=f"Password reset confirmed for user '{username}'",
        details={
            'success': success,
            'reset_completed_at': timezone.now().isoformat(),
            'ip_address_for_reset': get_client_ip(request)
        },
        severity='info' if success else 'warning'
    )


def log_permission_change(request, target_username, changed_permissions, change_type='role', user=None):
    """
    Log changes to user permissions or roles.
    
    Args:
        request: HTTP request object
        target_username: User whose permissions changed
        changed_permissions: List or dict of changed permissions
        change_type: 'role' or 'permission' or 'group'
        user: Admin user who made the change
    
    Audit Trail Note: Essential for detecting privilege escalation attacks
    """
    log_audit_event(
        event_type='auth_permission_change',
        request=request,
        username=target_username,
        user=user,
        description=f"Permissions changed for user '{target_username}' by admin",
        details={
            'change_type': change_type,
            'changed_permissions': str(changed_permissions),
            'changed_by_username': user.username if user else 'unknown',
            'changed_at': timezone.now().isoformat()
        },
        severity='warning'
    )


def log_suspicious_activity(request, activity_type, username=None, user=None, description="", details=None):
    """
    Log suspicious or anomalous activity detected by security controls.
    
    Args:
        request: HTTP request object
        activity_type: Type of suspicious activity detected
        username: Username associated with activity
        user: User object if authenticated
        description: Description of the suspicious activity
        details: Additional context
    
    Audit Trail Note: These events should be reviewed by security team
    """
    log_audit_event(
        event_type='security_suspicious_activity',
        request=request,
        username=username,
        user=user,
        description=description or f"Suspicious activity detected: {activity_type}",
        details=details or {'activity_type': activity_type},
        severity='error'
    )


# Admin utilities for reviewing audit logs

def get_user_audit_trail(user_or_username):
    """
    Get all audit events for a specific user.
    
    Args:
        user_or_username: User object or username string
    
    Returns:
        QuerySet of AuditLog entries for the user, ordered by timestamp (newest first)
    """
    if isinstance(user_or_username, User):
        username = user_or_username.username
    else:
        username = user_or_username
    
    return AuditLog.objects.filter(username=username).order_by('-timestamp')


def get_recent_security_events(hours=24):
    """
    Get recent high-severity security events.
    
    Args:
        hours: Number of hours to look back (default 24)
    
    Returns:
        QuerySet of high-severity security events from the past N hours
    """
    from datetime import timedelta
    then = timezone.now() - timedelta(hours=hours)
    return AuditLog.objects.filter(
        timestamp__gte=then,
        severity__in=['error', 'critical']
    ).order_by('-timestamp')


def get_failed_login_attempts(username=None, hours=24):
    """
    Get failed login attempts for a user or all users.
    
    Args:
        username: Specific username (None for all users)
        hours: Number of hours to look back
    
    Returns:
        QuerySet of failed login attempts
    """
    from datetime import timedelta
    then = timezone.now() - timedelta(hours=hours)
    
    query = AuditLog.objects.filter(
        event_type='auth_login_failure',
        timestamp__gte=then
    )
    
    if username:
        query = query.filter(username=username)
    
    return query.order_by('-timestamp')


def get_permission_changes(hours=24):
    """
    Get all permission/role changes in the past N hours.
    
    Useful for auditing admin activities.
    """
    from datetime import timedelta
    then = timezone.now() - timedelta(hours=hours)
    return AuditLog.objects.filter(
        event_type='auth_permission_change',
        timestamp__gte=then
    ).order_by('-timestamp')
