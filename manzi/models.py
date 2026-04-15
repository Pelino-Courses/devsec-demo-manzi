"""
User authentication models for the MANZI application.

This module provides models for user profile extensions and authentication tracking.
The core User model is provided by Django's built-in django.contrib.auth.models.User.
"""

from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    """
    Extended user profile model to store additional user information.
    
    This model extends Django's built-in User model using a one-to-one relationship.
    It allows storing additional profile information beyond what the User model provides.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, max_length=500, help_text="Brief biography (max 500 characters)")
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ['-created_at']

    def __str__(self):
        return f"Profile of {self.user.username}"


class LoginAttempt(models.Model):
    """
    Model to track login attempts for brute-force protection.
    
    This model records failed login attempts by username and IP address.
    It enables detection and prevention of brute-force attacks.
    
    Brute-force Protection Strategy:
    - Track failed attempts by USERNAME and IP ADDRESS
    - Hybrid approach: protects against both targeted attacks (same user, many IPs)
      and distributed attacks (many users, same IP or proxy)
    - Implement progressive cooldowns: longer delays after more failures
    - Account-based lockout: temp lock after threshold of failures
    
    Security Notes:
    - Stores username (not user FK) to track attempts before/without valid account
    - Records IP for distributed attack detection
    - Uses timestamps for time-based throttling and auto-cleanup
    - Records successful attempts for threat analysis
    """
    
    ATTEMPT_TYPE_CHOICES = [
        ('failed', 'Failed Login Attempt'),
        ('success', 'Successful Login'),
    ]
    
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    attempt_type = models.CharField(max_length=10, choices=ATTEMPT_TYPE_CHOICES, default='failed')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user_agent = models.TextField(blank=True, help_text="User-Agent header for tracking device/browser")
    
    class Meta:
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['attempt_type', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.get_attempt_type_display()} - {self.username} from {self.ip_address} at {self.timestamp}"


class AuditLog(models.Model):
    """
    Model for audit logging of security-relevant events.
    
    This model provides an immutable audit trail of security events including:
    - Authentication events (login, logout, registration)
    - Password changes and resets
    - Role/permission changes
    - Account modifications
    
    Design Principles:
    1. Immutability: Logs are never modified after creation
    2. Security: Never logs passwords or sensitive secrets
    3. Accountability: Records user, IP, and timestamp for all events
    4. Debuggability: Includes structured data for easy review
    5. Non-repudiation: Clearly identifies who did what and when
    
    Event Types:
    - auth_registration: User account created
    - auth_login_success: Successful login
    - auth_login_failure: Failed login attempt
    - auth_logout: User logged out
    - auth_password_change: User changed password
    - auth_password_reset_request: Password reset requested
    - auth_password_reset_confirm: Password successfully reset
    - auth_permission_change: User permissions/roles modified
    - security_suspicious_activity: Potential security issue detected
    
    Log Data Structure:
    {
        "event_type": "auth_login_success",
        "username": "john_doe",
        "user_id": 123,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "description": "User logged in successfully",
        "details": {
            "login_method": "username",
            "mfa_used": false,
            "session_duration_minutes": 30
        },
        "severity": "info",  # info, warning, error, critical
        "timestamp": "2024-01-15T10:30:00Z"
    }
    """
    
    EVENT_TYPE_CHOICES = [
        ('auth_registration', 'User Registration'),
        ('auth_login_success', 'Successful Login'),
        ('auth_login_failure', 'Failed Login'),
        ('auth_logout', 'Logout'),
        ('auth_password_change', 'Password Change'),
        ('auth_password_reset_request', 'Password Reset Request'),
        ('auth_password_reset_confirm', 'Password Reset Confirmed'),
        ('auth_permission_change', 'Permission/Role Change'),
        ('security_suspicious_activity', 'Suspicious Activity'),
    ]
    
    SEVERITY_CHOICES = [
        ('info', 'Information'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]
    
    # Core audit information
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    
    # User context (optional - some events before user exists)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    username = models.CharField(max_length=150, db_index=True)  # Username even if user deleted
    
    # Request context
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)
    
    # Event details
    description = models.TextField()  # Human-readable description
    details = models.JSONField(default=dict, blank=True)  # Structured data (never passwords!)
    
    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ['-timestamp']
        permissions = [
            ("view_audit_logs", "Can view audit logs"),
            ("export_audit_logs", "Can export audit logs"),
        ]
        indexes = [
            models.Index(fields=['event_type', '-timestamp']),
            models.Index(fields=['username', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.get_event_type_display()} - {self.username} at {self.timestamp}"
    
    @property
    def is_security_event(self):
        """Check if this is a high-priority security event"""
        security_events = ['auth_login_failure', 'security_suspicious_activity', 'auth_permission_change']
        return self.event_type in security_events or self.severity in ['error', 'critical']
