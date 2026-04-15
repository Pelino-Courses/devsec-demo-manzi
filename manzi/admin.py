"""
Django admin configuration for the MANZI authentication app.

This module registers models with the Django admin interface and configures
their display, filtering, and editing options.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile, LoginAttempt


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    Admin interface for UserProfile model.
    """
    list_display = ('user', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'created_at'

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Profile Details', {
            'fields': ('bio', 'date_of_birth', 'profile_picture')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def has_add_permission(self, request):
        """Prevent manual creation of UserProfile through admin."""
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """
    Admin interface for LoginAttempt model.
    
    Provides monitoring and analysis of login attempts for security auditing.
    Records failed and successful login attempts with IP, timestamp, and user-agent info.
    """
    list_display = ('username', 'ip_address', 'attempt_type', 'timestamp')
    list_filter = ('attempt_type', 'timestamp')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('timestamp', 'user_agent')
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Attempt Information', {
            'fields': ('username', 'attempt_type', 'timestamp')
        }),
        ('Network Information', {
            'fields': ('ip_address', 'user_agent')
        }),
    )
    
    def has_add_permission(self, request):
        """Prevent manual creation of login attempts through admin."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only allow deletion by superusers for audit trail"""
        return request.user.is_superuser
