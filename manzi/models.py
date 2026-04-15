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
