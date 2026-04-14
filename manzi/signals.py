"""
Signals for automatic UserProfile creation.

This module defines Django signals that automatically create a UserProfile
instance whenever a new User is created.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to create a UserProfile instance when a new User is created.
    
    This ensures every User has an associated UserProfile for storing additional information.
    """
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal handler to ensure UserProfile exists for every User.
    
    This handles cases where a User might exist without a profile.
    """
    try:
        instance.profile.save()
    except UserProfile.DoesNotExist:
        UserProfile.objects.create(user=instance)