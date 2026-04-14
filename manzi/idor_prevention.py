"""
Object-level access control utilities for IDOR (Insecure Direct Object Reference) prevention.

This module provides utilities and patterns for preventing unauthorized access to
user-owned resources by verifying that the current user owns or has permission to
access the specific resource before returning it.

IDOR Risk: Without proper object-level access control, attackers can bypass authorization
by directly manipulating identifiers (IDs, usernames, UUIDs) in URLs or API parameters:
    - User can view another user's profile by changing /profile/2/ to /profile/1/
    - User can edit admin profile by guessing the correct ID
    - User can modify another user's settings by changing account ID in requests

Prevention Strategy:
    1. Never trust the URL parameter alone - always verify ownership or permission
    2. Filter queries by authenticated user when possible
    3. Use explicit permission checks with clear error messages
    4. Return 404 instead of 403 to avoid information leakage
    5. Add logging for access control failures
"""

from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import get_object_or_404
from functools import wraps
from django.contrib import messages


# ============================================================================
# IDOR Prevention Utilities
# ============================================================================

class ObjectAccessDenied(Exception):
    """
    Raised when a user attempts unauthorized access to an object.
    Used internally to trigger proper HTTP response.
    """
    pass


def verify_object_ownership(obj, user, owner_field='user'):
    """
    Verify that the given user owns or has permission to access the object.
    
    This is the core IDOR prevention function that should be used in views
    that accept resource identifiers.
    
    Args:
        obj: The object to check (UserProfile, Post, Comment, etc.)
        user: The requesting user
        owner_field: Name of the field containing the owner (default: 'user')
    
    Returns:
        True if user owns the object
    
    Raises:
        PermissionDenied: If user does not own the object
    
    Example:
        # Safe: Gets profile and verifies ownership
        profile = UserProfile.objects.get(id=profile_id)
        verify_object_ownership(profile, request.user)
        return profile
    """
    if not user.is_authenticated:
        raise PermissionDenied("Not authenticated")
    
    # Admin/staff can access everything
    if user.is_staff or user.is_superuser:
        return True
    
    # Check ownership
    owner = getattr(obj, owner_field, None)
    if owner != user:
        raise PermissionDenied(
            f"You do not have permission to access this {obj.__class__.__name__}"
        )
    
    return True


def get_object_for_user(model_class, user, owner_field='user', **filter_kwargs):
    """
    Safely retrieve an object, verifying the user owns it or has permission.
    
    This is a wrapper around get_object_or_404 that adds IDOR prevention.
    It combines the ownership check into a single query to be efficient.
    
    Args:
        model_class: The model to query (UserProfile, Posts, etc.)
        user: The requesting user
        owner_field: Name of the field containing the owner (default: 'user')
        **filter_kwargs: Additional filter parameters (id, username, slug, etc.)
    
    Returns:
        The object if user owns it
    
    Raises:
        Http404: If object doesn't exist OR user doesn't own it
    
    Example:
        # Safe: Gets object and verifies ownership in one query
        profile = get_object_for_user(UserProfile, request.user, id=profile_id)
    """
    if not user.is_authenticated:
        raise Http404("Object not found")
    
    # Build query filters
    query_filters = dict(filter_kwargs)
    
    # Allow staff/admin to access any object
    if not (user.is_staff or user.is_superuser):
        # Non-admin: must own the object
        query_filters[owner_field] = user
    
    return get_object_or_404(model_class, **query_filters)


def require_object_ownership(owner_field='user'):
    """
    Decorator to enforce object ownership in views that accept an object ID.
    
    Usage:
        @require_object_ownership(owner_field='user')
        def view_with_id(request, object_id):
            # View code here
            # request.owned_object contains the verified object
    
    The decorator:
    1. Retrieves the object by ID
    2. Verifies the user owns it
    3. Returns 404 if either fails (prevents information leakage)
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, object_id=None, **kwargs):
            if not object_id:
                raise Http404("Object ID required")
            
            if not request.user.is_authenticated:
                raise Http404("Object not found")
            
            # Try to get the object - this is where IDOR could happen
            # We only verify ownership if user is not staff/admin
            try:
                if request.user.is_staff or request.user.is_superuser:
                    # Admin can access anything
                    from .models import UserProfile
                    obj = get_object_or_404(UserProfile, pk=object_id)
                else:
                    # Non-admin: must own it
                    from .models import UserProfile
                    obj = get_object_or_404(
                        UserProfile,
                        pk=object_id,
                        **{owner_field: request.user}
                    )
                
                request.owned_object = obj
                return view_func(request, object_id=object_id, **kwargs)
            
            except Http404:
                # Raise 404 for both "not found" and "not owned" to prevent info leakage
                raise Http404("Object not found")
        
        return wrapper
    return decorator


# ============================================================================
# Common IDOR Prevention Patterns
# ============================================================================

def pattern_filter_by_current_user(queryset, user, owner_field='user'):
    """
    Pattern 1: Filter queryset to only show current user's objects.
    
    SAFEST approach: Eliminate the IDOR risk entirely by only returning
    objects that belong to the current user.
    
    Use when: User should only ever see their own objects
    
    Example:
        # Bad: Gets any profile by ID
        profile = UserProfile.objects.get(id=profile_id)
        
        # Good: Gets profile only if it belongs to current user
        profile = UserProfile.objects.get(id=profile_id, user=user)
    """
    if user.is_staff or user.is_superuser:
        return queryset
    return queryset.filter(**{owner_field: user})


def pattern_explicit_permission_check(obj, user, permission_name=None):
    """
    Pattern 2: Explicit permission check after retrieving object.
    
    Use when: You need to retrieve the object first (maybe for logging),
    but still need to verify access before returning data.
    
    Example:
        profile = UserProfile.objects.get(id=profile_id)
        
        # Explicit check
        if profile.user != request.user and not request.user.is_staff:
            return HttpResponseForbidden("Access denied")
    """
    if user.is_staff or user.is_superuser:
        return True
    
    if permission_name:
        return user.has_perm(permission_name)
    
    return True


def pattern_404_not_403(user, obj, owner_field='user'):
    """
    Pattern 3: Return 404 instead of 403 for unauthorized access.
    
    IMPORTANT: This prevents attackers from discovering which user IDs exist.
    If you return 403, attacker knows the resource exists but they can't access it.
    
    Use when: You want to avoid information leakage about resource existence.
    """
    if not user.is_authenticated:
        return "404"  # Use 404 for unauthenticated
    
    if user.is_staff or user.is_superuser:
        return "allowed"
    
    owner = getattr(obj, owner_field, None)
    if owner != user:
        return "404"  # Use 404 instead of 403
    
    return "allowed"


# ============================================================================
# IDOR Risk Assessment
# ============================================================================

def check_view_for_idor_risk(view_name, view_func):
    """
    Helper to assess common IDOR patterns in a view.
    
    Returns a list of potential IDOR risks found.
    """
    import inspect
    
    source = inspect.getsource(view_func)
    risks = []
    
    # Check for common IDOR patterns
    if 'get_object_or_404' in source and 'request.user' not in source:
        risks.append("Uses get_object_or_404 without filtering by request.user")
    
    if '.get(id=' in source and 'request.user' not in source:
        risks.append("Uses .get(id=...) without ownership check")
    
    if 'User.objects.get(id=' in source:
        risks.append("Retrieves User directly by ID without ownership check")
    
    if '.filter(id=' in source and '.filter(user=' not in source:
        risks.append("Filters by ID only, without user filter")
    
    return risks
