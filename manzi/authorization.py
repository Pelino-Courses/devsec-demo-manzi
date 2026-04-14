"""
Authorization and permission management for the MANZI application.

This module provides decorators, utilities, and permission checks for
implementing role-based access control (RBAC) across the application.

Defined Roles:
- Anonymous: Unauthenticated users (no login required)
- Authenticated: Logged-in users with standard permissions
- Instructor/Staff: Users with elevated privileges (admin panel access)
- Admin: Superusers with full system access
"""

from functools import wraps
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User, Group
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse


# ============================================================================
# Role and Permission Constants
# ============================================================================

class Roles:
    """Defined role names in the system."""
    ANONYMOUS = 'anonymous'
    AUTHENTICATED = 'authenticated'
    INSTRUCTOR = 'instructor'
    STAFF = 'staff'
    ADMIN = 'admin'


class Permissions:
    """Custom permissions for the application."""
    VIEW_DASHBOARD = 'manzi.view_dashboard'
    EDIT_OWN_PROFILE = 'manzi.change_userprofile'
    CHANGE_PASSWORD = 'auth.change_password'
    VIEW_USER_LIST = 'auth.view_user'  # Staff only
    MANAGE_USERS = 'auth.add_user'  # Admin only
    ACCESS_ADMIN_PANEL = 'manzi.access_admin_panel'


# ============================================================================
# Authorization Decorators
# ============================================================================

def anonymous_only(view_func):
    """
    Decorator to restrict a view to anonymous (unauthenticated) users only.
    
    Redirects authenticated users to the dashboard.
    
    Usage:
        @anonymous_only
        def my_view(request):
            ...
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('manzi:dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


def authenticated_only(view_func):
    """
    Decorator to restrict a view to authenticated users only.
    
    Redirects anonymous users to the login page.
    Equivalent to @login_required but with custom messaging.
    
    Usage:
        @authenticated_only
        def my_view(request):
            ...
    """
    @login_required(login_url='manzi:login')
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        return view_func(request, *args, **kwargs)
    return wrapper


def instructor_required(view_func):
    """
    Decorator to restrict a view to Instructor role (or higher).
    
    Redirects unauthorized users with a 403 Forbidden response and a message.
    
    Usage:
        @instructor_required
        def admin_view(request):
            ...
    """
    @login_required(login_url='manzi:login')
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if has_instructor_role(request.user):
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You do not have permission to access this page.')
        return HttpResponseForbidden('Access Denied: Instructor role required.')
    return wrapper


def staff_required(view_func):
    """
    Decorator to restrict a view to Staff role (or higher).
    
    Redirects unauthorized users with a 403 Forbidden response and a message.
    
    Usage:
        @staff_required
        def staff_view(request):
            ...
    """
    @login_required(login_url='manzi:login')
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if has_staff_role(request.user):
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You do not have permission to access this page.')
        return HttpResponseForbidden('Access Denied: Staff role required.')
    return wrapper


def admin_required(view_func):
    """
    Decorator to restrict a view to Admin role (superusers only).
    
    Redirects unauthorized users with a 403 Forbidden response and a message.
    
    Usage:
        @admin_required
        def admin_view(request):
            ...
    """
    @login_required(login_url='manzi:login')
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if has_admin_role(request.user):
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You do not have permission to access this page.')
        return HttpResponseForbidden('Access Denied: Admin role required.')
    return wrapper


# ============================================================================
# Role Check Functions
# ============================================================================

def has_role(user, role_name):
    """
    Check if a user has a specific role.
    
    Args:
        user: Django User object
        role_name: Role name (from Roles class)
    
    Returns:
        bool: True if user has the role, False otherwise
    """
    if not user:
        return False
    
    if not user.is_authenticated:
        return role_name == Roles.ANONYMOUS
    
    if role_name == Roles.ADMIN:
        return user.is_superuser
    
    if role_name == Roles.AUTHENTICATED:
        return True
    
    # Check group membership for other roles
    return user.groups.filter(name=role_name).exists()


def has_anonymous_role(user):
    """Check if user is anonymous (unauthenticated)."""
    return not user.is_authenticated


def has_authenticated_role(user):
    """Check if user is authenticated."""
    return user.is_authenticated


def has_instructor_role(user):
    """Check if user has Instructor role or higher."""
    if not user.is_authenticated:
        return False
    return user.is_superuser or user.groups.filter(name=Roles.INSTRUCTOR).exists()


def has_staff_role(user):
    """Check if user has Staff role or higher."""
    if not user.is_authenticated:
        return False
    return user.is_superuser or user.is_staff or user.groups.filter(name=Roles.STAFF).exists()


def has_admin_role(user):
    """Check if user has Admin role (superuser)."""
    if not user.is_authenticated:
        return False
    return user.is_superuser


# ============================================================================
# Group and Permission Setup
# ============================================================================

def setup_authorization_groups():
    """
    Initialize all authorization groups and permissions in the database.
    
    Creates three main groups:
    - Instructor: Can view dashboards and manage courses
    - Staff: Can access staff panel and manage content
    - Admin: Full system access (superusers)
    
    This function should be run during initial setup or migrations.
    """
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType
    
    # Define groups and their permissions
    groups_config = {
        Roles.INSTRUCTOR: [
            'auth.view_user',
            'manzi.view_userprofile',
        ],
        Roles.STAFF: [
            'auth.view_user',
            'auth.change_user',
            'manzi.view_userprofile',
            'manzi.change_userprofile',
        ],
    }
    
    for group_name, permissions in groups_config.items():
        group, created = Group.objects.get_or_create(name=group_name)
        
        for perm_codename in permissions:
            try:
                if '.' in perm_codename:
                    app_label, codename = perm_codename.split('.')
                else:
                    codename = perm_codename
                
                permission = Permission.objects.get(codename=codename)
                group.permissions.add(permission)
            except Permission.DoesNotExist:
                pass
        
        status = "created" if created else "updated"
        print(f"Group '{group_name}' {status} with {group.permissions.count()} permissions")


def assign_role_to_user(user, role_name):
    """
    Assign a role to a user by adding them to the appropriate group.
    
    Args:
        user: Django User object
        role_name: Role name (from Roles class)
    
    Returns:
        bool: True if assignment successful, False otherwise
    """
    if not user.is_authenticated:
        return False
    
    if role_name == Roles.ADMIN:
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return True
    
    if role_name == Roles.ANONYMOUS:
        return False  # Cannot assign anonymous role to authenticated user
    
    try:
        group = Group.objects.get(name=role_name)
        user.groups.add(group)
        return True
    except Group.DoesNotExist:
        return False


def remove_role_from_user(user, role_name):
    """
    Remove a role from a user by removing them from the group.
    
    Args:
        user: Django User object
        role_name: Role name (from Roles class)
    
    Returns:
        bool: True if removal successful, False otherwise
    """
    if not user.is_authenticated:
        return False
    
    if role_name == Roles.ADMIN:
        user.is_superuser = False
        user.is_staff = False
        user.save()
        return True
    
    if role_name == Roles.ANONYMOUS:
        return False
    
    try:
        group = Group.objects.get(name=role_name)
        user.groups.remove(group)
        return True
    except Group.DoesNotExist:
        return False


def get_user_roles(user):
    """
    Get all roles assigned to a user.
    
    Args:
        user: Django User object
    
    Returns:
        list: List of role names the user has
    """
    if not user:
        return [Roles.ANONYMOUS]
    
    if not user.is_authenticated:
        return [Roles.ANONYMOUS]
    
    roles = [Roles.AUTHENTICATED]
    
    if user.is_superuser:
        roles.append(Roles.ADMIN)
    
    for group in user.groups.all():
        if group.name in [Roles.INSTRUCTOR, Roles.STAFF]:
            roles.append(group.name)
    
    return roles


# ============================================================================
# Context Processors
# ============================================================================

def authorization_context(request):
    """
    Context processor to add authorization information to template context.
    
    Add to TEMPLATES['OPTIONS']['context_processors'] in settings.py
    """
    context = {
        'user_roles': get_user_roles(request.user),
        'is_anonymous': has_anonymous_role(request.user),
        'is_authenticated': has_authenticated_role(request.user),
        'is_instructor': has_instructor_role(request.user),
        'is_staff': has_staff_role(request.user),
        'is_admin': has_admin_role(request.user),
    }
    return context
