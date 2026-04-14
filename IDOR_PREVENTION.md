# IDOR Prevention: Design & Implementation

## Overview

This document describes the IDOR (Insecure Direct Object Reference) prevention implementation in the MANZI application. IDOR is a critical vulnerability where users can access unauthorized resources by directly manipulating identifiers (URLs, IDs, usernames) without proper permission checks.

## The IDOR Vulnerability

### What Is IDOR?

IDOR occurs when an application fails to verify that the user requesting access to a resource actually owns or has permission to access that specific resource.

### Real-World Example

**Vulnerable Code:**
```python
@login_required
def view_profile(request, user_id):
    # VULNERABLE! No ownership check
    user = User.objects.get(id=user_id)
    profile = UserProfile.objects.get(user=user)
    return render(request, 'profile.html', {'profile': profile})
```

**Attack:**
1. Alice logs in and visits `/profile/view/1/` to see her profile
2. Alice guesses that if she changes URL to `/profile/view/2/`, she might see Bob's profile
3. **IDOR Success**: Alice can now view, and potentially modify, Bob's personal data

### Impact

- **Confidentiality Breach**: Users can view other users' private information
- **Integrity Violation**: Users can modify other users' data
- **Availability**: Users might delete other users' accounts or data
- **OWASP #1**: IDOR is part of "Broken Access Control" - ranked #1 in OWASP Top 10

## Prevention Strategy

MANZI implements IDOR prevention through multiple layers:

### Layer 1: Role-Based Access Control (RBAC)

Restrict who can access object manipulation endpoints:

```python
@staff_required  # Only staff/admin can access
def view_user_profile(request, user_id):
    ...
```

### Layer 2: Ownership Verification

Verify the user owns the object or has explicit permission:

```python
def view_own_profile(request):
    # SAFE: Filter by current user only
    profile = UserProfile.objects.get(user=request.user)
    return render(request, 'profile.html', {'profile': profile})
```

### Layer 3: Explicit Permission Checks

For endpoints that accept resource IDs, verify permission explicitly:

```python
def edit_profile(request, user_id):
    # Get the profile
    profile = UserProfile.objects.get(id=user_id)
    
    # IDOR PREVENTION: Explicit ownership check
    if profile.user != request.user and not request.user.is_staff:
        raise Http404("Profile not found")  # 404, not 403
    
    # Safe to proceed
    ...
```

## Implementation Details

### Safe Patterns

#### Pattern 1: Filter by Current User (Safest)

Eliminate the IDOR risk by only querying for the current user's objects:

```python
@authenticated_only
def view_own_profile(request):
    # SAFE: Only gets current user's profile
    profile = UserProfile.objects.get(user=request.user)
    return render(request, 'profile.html', {'profile': profile})
```

**Advantages:**
- Eliminates IDOR completely
- Simplest and most maintainable
- No need to check IDs

**Use When:**
- User should only ever see their own objects

#### Pattern 2: Use get_object_for_user() Helper

Use the provided helper function for safer access:

```python
from manzi.idor_prevention import get_object_for_user

@authenticated_only
def view_profile(request):
    # SAFE: Helper ensures user owns object
    profile = get_object_for_user(
        UserProfile,
        request.user,
        user=request.user  # Filter by ownership
    )
    return render(request, 'profile.html', {'profile': profile})
```

#### Pattern 3: Explicit Permission Check

For endpoints that require accepting resource IDs (like admin views):

```python
@staff_required  # Role-based access control first
def admin_view_profile(request, user_id):
    try:
        profile = UserProfile.objects.get(id=user_id)
        
        # IDOR PREVENTION: Explicit permission check
        # Staff can view any profile, but verify it
        if not (request.user.is_staff or request.user.is_superuser):
            raise Http404("Profile not found")
        
        return render(request, 'profile.html', {'profile': profile})
    
    except UserProfile.DoesNotExist:
        # Return 404 to prevent info leakage
        raise Http404("Profile not found")
```

### Critical Details

#### Return 404, Not 403

Return HTTP 404 (Not Found) instead of HTTP 403 (Forbidden) for unauthorized access:

```python
# BAD: Tells attacker the resource EXISTS
if profile.user != request.user:
    return HttpResponseForbidden("Access denied")

# GOOD: Hides whether resource exists
if profile.user != request.user:
    raise Http404("Profile not found")
```

**Why?**
- 403 tells attacker: "This resource exists, but you can't access it"
- 404 doesn't leak whether the resource exists
- Prevents information gathering during attacks

#### Combine with RBAC

IDOR prevention works best with role-based access control:

```python
# Step 1: Check role (decorator)
@staff_required

# Step 2: Get object (may not exist)
def view_user(request, user_id):
    profile = UserProfile.objects.get(id=user_id)  # 404 if not found
    
    # Step 3: Verify permission (shouldn't be needed, but be safe)
    if not (request.user.is_staff or request.user.is_superuser):
        raise Http404("Profile not found")
```

## Views and IDOR Prevention

### Current Implementation

#### Safe Views (No IDOR Risk)

1. **profile_view()**
   - Filters by `user=request.user`
   - Doesn't accept user ID parameters
   - Only current user can see their own profile
   - **Risk Level**: Minimal

2. **profile_edit_view()**
   - Filters by `user=request.user`
   - Can only edit own profile
   - **Risk Level**: Minimal

3. **dashboard_view()**
   - Filters by `user=request.user`
   - Only shows current user's dashboard
   - **Risk Level**: Minimal

#### Protected Views (Requires Authorization)

1. **user_profile_view(user_id)**
   - Accepts user_id parameter
   - Protected by `@staff_required` decorator
   - Explicit permission check included
   - Returns 404 for nonexistent/unauthorized access
   - **Risk Level**: Low (role-based + explicit check)

2. **user_profile_edit_admin(user_id)**
   - Accepts user_id parameter
   - Protected by `@staff_required` decorator
   - Only staff/admin can edit other profiles
   - **Risk Level**: Low

3. **user_list_view()**
   - Protected by `@instructor_required` decorator
   - Lists all users (no individual object access)
   - **Risk Level**: Low

## Utilities Provided

### verify_object_ownership()

Check if user owns an object:

```python
from manzi.idor_prevention import verify_object_ownership
from django.core.exceptions import PermissionDenied

@authenticated_only
def edit_profile(request, profile_id):
    profile = UserProfile.objects.get(id=profile_id)
    
    # Verify ownership
    try:
        verify_object_ownership(profile, request.user)
    except PermissionDenied:
        raise Http404("Profile not found")
    
    # Safe to edit
    return update_profile(profile, request.POST)
```

### get_object_for_user()

Safely retrieve an object with ownership verification:

```python
from manzi.idor_prevention import get_object_for_user

profile = get_object_for_user(
    UserProfile,
    request.user,
    user=request.user  # Must own or be staff
)
```

**Advantages:**
- Single query filter
- Automatic 404 on no match
- Staff automatically allowed
- Clean and readable

### require_object_ownership()

Decorator for views that accept object IDs:

```python
from manzi.idor_prevention import require_object_ownership

@require_object_ownership(owner_field='user')
@authenticated_only
def edit_object(request, object_id):
    obj = request.owned_object  # Already verified
    # Safe to proceed
    ...
```

## Testing IDOR Prevention

Comprehensive test file: `tests_idor_prevention.py`

### Test Categories

1. **Ownership Tests** (IDORPreventionTest)
   - User can access own profile
   - User cannot access other users' profiles
   - Edits only affect own profile

2. **Admin Access Tests** (AdminProfileManipulationTest)
   - Staff can access any profile
   - Regular users cannot access admin endpoints
   - Modifications are logged/audited

3. **URL Manipulation Tests** (URLManipulationTest)
   - Changing user IDs doesn't bypass access
   - Invalid IDs return proper errors
   - Negative IDs handled safely

4. **Boundary Cases** (AccessControlBoundaryCases)
   - Missing authentication
   - Invalid role
   - Nonexistent resources
   - Edge case IDs

### Running Tests

```bash
# All IDOR tests
python manage.py test manzi.tests_idor_prevention -v 2

# Specific test class
python manage.py test manzi.tests_idor_prevention.IDORPreventionTest

# Specific test
python manage.py test manzi.tests_idor_prevention.IDORPreventionTest.test_user_cannot_view_other_profile_page
```

## Common Mistakes to Avoid

### ❌ Mistake 1: Only Check Authentication

```python
@login_required  # VULNERABLE!
def view_profile(request, profile_id):
    profile = UserProfile.objects.get(id=profile_id)
    return render(request, 'profile.html', {'profile': profile})
```

**Problem**: Anyone logged in can view any profile

**Fix**: Add ownership check
```python
@login_required
def view_profile(request, profile_id):
    profile = get_object_for_user(UserProfile, request.user, id=profile_id)
    return render(request, 'profile.html', {'profile': profile})
```

### ❌ Mistake 2: Return 403 to User

```python
if profile.user != request.user:
    return HttpResponseForbidden("Access denied")  # Leaked information!
```

**Problem**: Attacker learns which profile IDs exist

**Fix**: Return 404
```python
if profile.user != request.user:
    raise Http404("Profile not found")
```

### ❌ Mistake 3: Trust User Input

```python
# VULNERABLE!
owner_id = request.GET.get('user_id')
profile = UserProfile.objects.get(id=owner_id)
```

**Problem**: User can set any ID

**Fix**: Use authentication, not input
```python
# SAFE
profile = UserProfile.objects.get(user=request.user)
```

### ❌ Mistake 4: Inconsistent Checks

```python
def edit_profile(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    
    if request.method == 'POST':
        # Check ownership - but only on POST!
        if profile.user != request.user:
            raise Http404()
        # Vulnerable on GET!
```

**Problem**: Inconsistent authorization

**Fix**: Check on all methods
```python
profile = get_object_for_user(UserProfile, request.user, id=profile_id)
# Works for GET, POST, PUT, DELETE, etc.
```

## IDOR Risk Assessment

### How to Spot Potential IDOR

Review views for these patterns:

1. **Accepts ID parameter**
   ```python
   def view_data(request, data_id):  # ⚠️ Check for IDOR
   ```

2. **Retrieves object by ID**
   ```python
   obj = Model.objects.get(id=request.GET.get('id'))  # ⚠️ Check
   ```

3. **No ownership filter in query**
   ```python
   post = Post.objects.get(id=post_id)  # ⚠️ Should filter by user
   ```

4. **Only @login_required decorator**
   ```python
   @login_required
   def edit_comment(request, comment_id):  # ⚠️ Need ownership check
   ```

### Checklist for Secure Implementation

For each view that accepts a resource ID:

- [ ] Does it verify authentication? (`@login_required` or `authenticated_only`)
- [ ] Does it verify the user owns the resource?
- [ ] Does it filter queries by `request.user` when possible?
- [ ] Does unauthorized access return 404 (not 403)?
- [ ] Are there tests for both allowed and denied access?
- [ ] Was the implementation reviewed for IDOR?

## Security Decisions

1. **Filter by Current User First**: Eliminates IDOR completely for user-owned resources
2. **Use Helpers**: `get_object_for_user()` and `verify_object_ownership()` reduce mistakes
3. **444 Not 403**: Prevents information leakage about resource existence
4. **Role + Verification**: Combine @staff_required with ownership checks
5. **Comprehensive Tests**: Test both success and failure paths

## Future Enhancements

1. **Automatic Checks**: Middleware that logs potential IDOR attempts
2. **Audit Trail**: Log all object access for security monitoring
3. **Rate Limiting**: Detect and block sequential ID enumeration
4. **Debug Mode Warning**: Django debug page warns about IDOR risks
5. **Automated Testing**: Framework to detect IDOR patterns automatically

## Related OWASP Resources

- [OWASP Testing Guide: IDOR](https://owasp.org/www-community/attacks/IDOR_attack)
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html#:~:text=insecure%20direct%20object)

## Summary

The MANZI application implements comprehensive IDOR prevention through:

1. ✅ Role-based access control on sensitive endpoints
2. ✅ Explicit ownership verification for object access
3. ✅ Filtering queries by current user when possible
4. ✅ Returning 404 instead of 403 to prevent information leakage
5. ✅ Comprehensive tests covering both allowed and denied access
6. ✅ Reusable utilities for common IDOR prevention patterns
7. ✅ Clear documentation and code comments

This multi-layered approach makes it difficult for attackers to discover or exploit IDOR vulnerabilities.
