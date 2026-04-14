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
