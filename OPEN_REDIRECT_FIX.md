# Open Redirect Vulnerability Fix

**Learning Objective:** Analyze redirect safety in authentication flows and prevent open redirect behavior.

## Table of Contents

1. [Vulnerability Overview](#vulnerability-overview)
2. [Attacks and Impact](#attacks-and-impact)
3. [Root Causes](#root-causes)
4. [Vulnerabilities Found](#vulnerabilities-found)
5. [Fixes Implemented](#fixes-implemented)
6. [Implementation Details](#implementation-details)
7. [Testing Strategy](#testing-strategy)
8. [Deployment Guide](#deployment-guide)
9. [Common Mistakes](#common-mistakes)

---

## Vulnerability Overview

### What is an Open Redirect?

An **open redirect** vulnerability occurs when an application redirects users to a URL supplied by the user without proper validation.

### Severity: Medium to High

- **CWE-601:** URL Redirection to Untrusted Site
- **OWASP:** Open Redirect
- **Impact:** Phishing, credential theft, malware distribution
- **Likelihood:** Common in authentication flows

### How It Works

```
1. Attacker crafts malicious URL:
   https://devsec-demo.herokuapp.com/login/?next=https://evil.com

2. Attacker sends URL to victim (email, chat, social media)
   "Click here to log in to your account"

3. Victim clicks (URL looks legitimate - devsec-demo domain)

4. Login form appears (legitimate)

5. Victim enters credentials and logs in

6. Redirection happens:
   Expected: User sees dashboard
   Actual: Redirected to https://evil.com

7. Attacker's phishing site appears
   - Looks similar to devsec-demo
   - Victim might not notice the URL change
   - Attacker can prompt for "additional verification"
   - Steals additional credentials, credit card, etc.
```

### Why This Works

- URL looks legitimate up to the login point
- Users don't always check where they're redirected to
- Redirects are common and expected in web apps
- Victim is already in "authenticated" mindset after login

---

## Attacks and Impact

### Attack Scenario 1: Credential Harvesting

```
Email from "devsec-demo Support":
"Your session expired. Click here to log in again:"
https://devsec-demo.herokuapp.com/login/?next=https://attacker.com/phishing

User clicks → Logs in → Redirected to attacker.com phishing page
```

**Impact:**
- Secondary credentials stolen (email + password)
- Access to other accounts (password reuse)
- Reset credentials to attacker's email

### Attack Scenario 2: Malware Distribution

```
Social Media Post:
"This new feature just dropped! Check it out:"
https://devsec-demo.herokuapp.com/login/?next=https://malware-host.com

User clicks → After login → Redirected to malware site
```

**Impact:**
- Browser exploit
- Malware download
- System compromise

### Attack Scenario 3: Phishing Campaign

```
Bulk Email:
"Verify your account immediately:"
https://devsec-demo.herokuapp.com/logout/?next=https://evil-login-clone.com

User clicks → Sees fake devsec-demo login  → Enters credentials
```

**Impact:**
- Wholesale credential theft
- Access to thousands of legitimate accounts

### Attack Scenario 4: OAuth Token Theft

```
Login with OAuth:
https://devsec-demo.herokuapp.com/login/?next=https://attacker.com

After authentication:
Redirect includes access token in URL or cookie
```

**Impact:**
- OAuth token intercepted by attacker
- Attacker can impersonate user
- Access to integrated services

---

## Root Causes

### Root Cause 1: Unvalidated User Input

```python
# VULNERABLE PATTERN
next_url = request.GET.get('next', 'manzi:dashboard')
return redirect(next_url)  # ← Direct use of untrusted input
```

**Problem:**
- GET parameter directly used in redirect
- No validation of destination
- Attacker fully controls where user goes

### Root Cause 2: Assumption of Safe URLs

```python
# DANGEROUS ASSUMPTION
if next_url.startswith('/'):
    # Assumed safe because it starts with /
    return redirect(next_url)

# Can be bypassed with:
# /login/?next=//evil.com  (protocol-relative)
```

**Problem:**
- Incomplete validation
- Protocol-relative URLs bypass check
- URL encoding bypasses simple checks

### Root Cause 3: Trust in Framework Defaults

```python
# INCORRECT BELIEF
# "Django's redirect() function is safe"
# Some frameworks' redirect() do validate, but

return redirect(request.GET.get('next'))  # ← Not validated beforehand
```

**Problem:**
- `redirect()` function doesn't validate redirects
- It just sends HTTP Location header
- Input validation is developer's responsibility

### Root Cause 4: Missing Whitelist

```python
# NO WHITELIST
# Any internal-looking URL accepted
# Can be exploited with creative paths

/login/?next=/admin/delete-user/
/login/?next=/api/migrate-to-attacker-account
```

**Problem:**
- No list of legitimate redirect destinations
- Any internal URL allowed, even dangerous ones
- Attacker can engineer creative paths

---

## Vulnerabilities Found

### Vulnerability 1: Login View - Unsafe Redirect

**Location:** `manzi/views.py`, lines 169-170

**VULNERABLE CODE:**
```python
# Redirect to next page or dashboard
next_url = request.GET.get('next', 'manzi:dashboard')
return redirect(next_url)
```

**VULNERABILITY:**
- `next` parameter from GET is used directly
- No validation of destination
- Attacker can set `?next=https://evil.com`
- User redirected to attacker site after login

**PROOF OF CONCEPT:**
```
https://yoursite.com/login/?next=https://attacker.com
1. User logs in successfully
2. URL is: https://attacker.com (UNSAFE!)
3. Attacker can phish credentials
```

### Vulnerability 2: Password Reset Redirect (Potential)

**Location:** `manzi/views.py`, password_reset_confirm_view

**Analysis:** Currently redirects to:
```python
return redirect('manzi:password_reset_request')
return redirect('manzi:login')
```

**Status:** ✅ Safe (hardcoded URLs, not user input)

### Vulnerability 3: Logout Redirect (Potential)

**Location:** `manzi/views.py`, logout_view

**Current Code:**
```python
return redirect('manzi:login')
```

**Status:** ✅ Safe (hardcoded, but could accept next parameter)

---

## Fixes Implemented

### Fix 1: Safe Redirect Utility Module

**File:** `manzi/redirect_safety.py` (NEW)

Provides three levels of protection:

#### Level 1: Basic Validation
```python
is_safe_redirect_url(url)
# Returns True if URL is safe, False otherwise
# Uses Django's url_has_allowed_host_and_scheme()
```

**Security Checks:**
- No dangerous schemes (javascript:, data:, etc.)
- No external domains
- No CRLF injection
- Properly formatted URL

#### Level 2: Safe Fallback
```python
get_safe_redirect_url(url, default_url)
# If URL is safe: return it
# If URL is unsafe: return safe default
```

**Advantage:**
- Never fails or crashes
- Always redirects somewhere safe
- No complicated error handling

#### Level 3: Request Integration
```python
validate_redirect_from_request(request, param_name='next', default_url='manzi:dashboard')
# Extracts redirect from request
# Validates it
# Returns safe URL ready to use
```

**Recommended Pattern:**
```python
safe_url = validate_redirect_from_request(request)
return redirect(safe_url)
```

### Fix 2: Updated Login View

**File:** `manzi/views.py`, login_view, lines 169-173

**FIXED CODE:**
```python
# SECURITY FIX: Validate redirect before using it
# Prevents open redirect attacks in the 'next' parameter
next_url = validate_redirect_from_request(
    request,
    param_name='next',
    default_url='manzi:dashboard'
)
return redirect(next_url)
```

**Security Improvements:**
1. Uses `validate_redirect_from_request()`
2. Validates against external redirects
3. Falls back to safe default
4. Never redirects to attack domain

**Attack Prevention:**
```
BEFORE FIX:
GET /login/?next=https://evil.com
→ User redirected to evil.com (VULNERABLE)

AFTER FIX:
GET /login/?next=https://evil.com
→ Validation rejects evil.com
→ User redirected to dashboard (SAFE)
```

---

## Implementation Details

### Django's Built-in Protection

The fix uses Django's `url_has_allowed_host_and_scheme()`:

```python
from django.utils.http import url_has_allowed_host_and_scheme

# Validates URL is safe
is_safe = url_has_allowed_host_and_scheme(
    url='https://evil.com',
    allowed_hosts=None,  # Only internal URLs allowed
    require_https=False
)
# Returns False
```

### How It Works

1. **Scheme Validation:**
   - Rejects `javascript:`, `data:`, etc.
   - Prevents XSS vectors
   - Allows `http://`, `https://`, `/`, `//`

2. **Host Validation:**
   - Checks if domain is in `allowed_hosts`
   - If `allowed_hosts=None`, only relative URLs safe
   - Can allow specific external domains if needed

3. **Format Validation:**
   - Checks URL is properly formatted
   - Prevents CRLF injection
   - Handles URL encoding

### Code Flow

```
Request received with ?next=value
    ↓
validate_redirect_from_request(request, 'next', 'manzi:dashboard')
    ↓
Extract: next = request.GET.get('next')
    ↓
Validate: is_safe_redirect_url(next)
    ├─ YES: Use next URL
    ├─ NO: Use default 'manzi:dashboard'
    ↓
return redirect(safe_url)
    ↓
User redirected to SAFE location
```

---

## Testing Strategy

### Test Coverage: 27 Tests

#### Category 1: Utility Function Tests (13 tests)
- Safe internal redirects accepted
- Unsafe external redirects rejected
- Protocol-relative URLs rejected
- JavaScript schemes rejected
- Data schemes rejected
- Edge cases handled gracefully

**Examples:**
```python
✓ test_safe_internal_redirect_absolute()
✓ test_unsafe_external_redirect_https()
✓ test_unsafe_protocol_relative_redirect()
✓ test_unsafe_javascript_redirect()
```

#### Category 2: Login Flow Tests (6 tests)
- Safe redirects after login work
- Unsafe redirects rejected
- External domains blocked
- Protocol-relative URLs blocked
- JavaScript in redirect blocked
- Missing parameter uses default

**Examples:**
```python
✓ test_login_with_safe_next_parameter()
✓ test_login_with_unsafe_next_parameter()
✓ test_login_with_protocol_relative_next()
```

#### Category 3: Edge Case Tests (5 tests)
- Newlines in URLs
- Encoded domains
- Unicode domains
- Multiple slashes
- Whitespace characters

#### Category 4: Educational Tests (3 tests)
- Attack patterns documented
- Defense mechanisms documented
- Design insights captured

### Running Tests

```bash
# Run all open redirect tests
python manage.py test manzi.tests_open_redirect -v 2

# Run specific test category
python manage.py test manzi.tests_open_redirect.SafeRedirectUtilityTests

# Run specific test
python manage.py test manzi.tests_open_redirect.OpenRedirectLoginTests.test_login_with_unsafe_next_parameter

# Test results: 27 tests, all passing ✓
```

---

## Deployment Guide

### Step 1: Review Changes

- `redirect_safety.py` - New utility module (82 lines, heavily documented)
- `views.py` - Import added, login_view updated (5 lines changed)
- `tests_open_redirect.py` - 27 comprehensive tests (350 lines)

### Step 2: Verify Tests Pass

```bash
python manage.py test manzi.tests_open_redirect
# Expected: Ran 27 tests - OK
```

### Step 3: Test in Development

```bash
python manage.py runserver

# Test safe redirect
http://localhost:8000/login/?next=/profile/
→ After login: Redirected to /profile/ ✓

# Test unsafe redirect
http://localhost:8000/login/?next=https://evil.com
→ After login: Redirected to /dashboard/ (default, safe) ✓
```

### Step 4: Deploy to Production

- Merge PR into main branch
- Deploy as usual
- Monitor logs for any issues

### Step 5: Verify in Production

```bash
# Safe redirect
POST /login/ with ?next=/profile/
Expected: Redirected to /profile/ ✓

# Unsafe redirect
POST /login/ with ?next=https://evil.com
Expected: Redirected to /dashboard/ ✓
```

---

## Common Mistakes

### ❌ Mistake 1: Partial URL Validation

```python
# WRONG: Only checks if starts with /
if next_url.startswith('/'):
    return redirect(next_url)

# Can be bypassed with:
# //evil.com (protocol-relative, starts with /)
# /javascript:alert('xss') (no, but other bypasses exist)
```

**Why It Fails:**
- Protocol-relative URLs start with //
- Bypasses the startswith('/') check
- Browser interprets as same protocol

**Fix:**
```python
# RIGHT: Use Django's validation
if is_safe_redirect_url(next_url):
    return redirect(next_url)
```

### ❌ Mistake 2: Simple Whitelist Without Validation

```python
# WRONG: Whitelist without proper URL parsing
SAFE_URLS = ['/profile/', '/settings/', '/logout/']

if next_url in SAFE_URLS:
    return redirect(next_url)

# Can be partially bypassed - but better than no validation
# But still vulnerable if whitelisted URL has parameters
```

**Why It Fails:**
- Doesn't catch all encoded variants
- Can't handle parameters properly
- Difficult to maintain whitelist

**Fix:**
```python
# RIGHT: Use Django's function + optional whitelist
if is_safe_redirect_url(next_url):
    # Optional: Additional whitelisting
    if next_url in ALLOWED_URLS or next_url.startswith('/'):
        return redirect(next_url)
```

### ❌ Mistake 3: Trusting URL Parser

```python
# WRONG: Using URL parser instead of validator
from urllib.parse import urljoin

next_url = request.GET.get('next')
parsed = urljoin(request.build_absolute_uri('/'), next_url)
# Doesn't validate!!
return redirect(parsed)
```

**Why It Fails:**
- URL parsing ≠ URL validation
- Parser builds valid URLs from both safe and unsafe input
- Doesn't reject evil.com

**Fix:**
```python
# RIGHT: Validate before using
if is_safe_redirect_url(next_url):
    return redirect(next_url)
```

### ❌ Mistake 4: Forgetting Edge Cases

```python
# WRONG: Assumes simple cases only
if 'evil.com' not in next_url:
    return redirect(next_url)

# Can be bypassed with:
# - Encoded domains: %65vil.com
# - Case variations: EVIL.COM
# - Similar domains: evil-com.com
# - Homograph attacks: еvil.com (Cyrillic e)
```

**Why It Fails:**
- Blacklist can't cover all cases
- New bypass techniques discovered constantly

**Fix:**
```python
# RIGHT: Use whitelist + Django's validator
# Reject by default, only allow known good patterns
if is_safe_redirect_url(next_url):
    return redirect(next_url)
```

### ❌ Mistake 5: Crashing on Invalid Input

```python
# WRONG: Crashes if next_url is None
next_url = request.GET.get('next')
return redirect(next_url)  # Crashes if None!
```

**Why It Fails:**
- 500 error for users without ?next parameter
- Bad user experience
- Potential DoS by sending many requests with missing next

**Fix:**
```python
# RIGHT: Always provide fallback
next_url = validate_redirect_from_request(
    request,
    param_name='next',
    default_url='manzi:dashboard'  # ← Falls back gracefully
)
return redirect(next_url)
```

---

## Security Decisions Made

### Decision 1: Django's url_has_allowed_host_and_scheme()

**Rationale:**
- Battle-tested in Django framework itself
- Handles edge cases and encoding
- No reinventing the wheel

**Alternative Considered:**
- Custom validation function
- Rejected: Would be less robust
- Risk of missing edge cases

### Decision 2: Validating Before Using

**Rationale:**
- Fail-safe pattern
- Always validates regardless of path
- One place for all redirect logic

**Alternative Considered:**
- Custom logic in each view
- Rejected: Duplicates code, increases bugs

### Decision 3: Safe Default on Validation Failure

**Rationale:**
- Never crashes or shows error
- User still sees their account/dashboard
- Better UX than error page

**Alternative Considered:**
- Error message if redirect unsafe
- Rejected: Leaks info, poor UX

### Decision 4: Utility Module Separate from Views

**Rationale:**
- Reusable in other views
- Can be imported by other apps
- Testable in isolation

**Alternative Considered:**
- Inline in login_view
- Rejected: Would duplicate in logout_view, etc.

---

## Checklist for Reviewers

- [ ] No direct `redirect(request.GET.get(...))` without validation
- [ ] All redirects after authentication validated
- [ ] Tests cover safe and unsafe cases
- [ ] Documentation explains vulnerability
- [ ] Uses `validate_redirect_from_request()` or equivalent
- [ ] Graceful fallback on validation failure
- [ ] Works with existing user workflows
- [ ] No breaking changes to legitimate use

---

## References

### Security Standards
- [OWASP: Open Redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger: Open Redirects](https://portswigger.net/web-security/open-redirection)

### Django Documentation
- [url_has_allowed_host_and_scheme()](https://docs.djangoproject.com/en/stable/api/django-utils-http/#django.utils.http.url_has_allowed_host_and_scheme)
- [Redirect Function](https://docs.djangoproject.com/en/stable/shortcuts/#redirect)
- [URL Dispatching](https://docs.djangoproject.com/en/stable/topics/http/urls/)

### Related Vulnerabilities
- Similar vulnerability: IDOR (Insecure Direct Object Reference)
- Related: CRLF Injection
- Related: XSS via JavaScript: scheme

---

## Summary

The open redirect vulnerability was fixed by:

1. **Creating `redirect_safety.py`** - Reusable validation utilities
2. **Updating `login_view`** - Using safe redirect validation
3. **Writing 27 tests** - Covering safe/unsafe cases
4. **Documenting thoroughly** - Attack patterns and defenses

**Key Learning Points:**
- Never redirect to user-supplied URLs without validation
- Use framework-provided validators (Django's `url_has_allowed_host_and_scheme()`)
- Always provide safe default on validation failure
- Test both safe and unsafe redirect attempts
- Document security decisions for future maintainers

The fix ensures all post-authentication redirects are safe while maintaining legitimate user workflows and good user experience.
