# Audit Logging for Security Events

## Overview

This document describes the audit logging implementation for the DevSec Demo authentication system. Audit logging provides accountability, enables forensic analysis, and allows for detection of security incidents through structured event tracking.

**Key Principle**: NEVER log sensitive data like passwords or tokens. Log the EVENT and CONTEXT, not the secrets.

---

## Why Audit Logging Matters

### Security Benefits

1. **Accountability**: Know WHO did WHAT, WHEN, and FROM WHERE
2. **Detection**: Identify suspicious patterns (e.g., failed login storms)
3. **Forensics**: Investigate security incidents with complete timeline
4. **Compliance**: Meet audit and regulatory requirements
5. **Deterrence**: Knowledge of logging may discourage attacks

### Real-World Examples

**Example 1: Brute-Force Attack Detection**
- Attacker tries 100 login attempts in 5 minutes for user "admin"
- Audit logs show multiple `auth_login_failure` events from single IP
- Security team can block IP and reset admin password

**Example 2: Compromised Account Recovery**
- User reports unauthorized access
- Audit logs show login from unusual IP at 3:00 AM
- Logs reveal password changed at 2:59 AM from same unusual IP
- Attacker's actions are fully documented for incident response

**Example 3: Insider Threat Detection**
- Instructor account reports that students' grades were changed
- Audit logs show staff member edited grades for specific students
- Permission change logs show who made whom admin
- Complete chain of custody established for investigation

---

## What Gets Logged

### Event Types

The system logs these security-relevant events:

#### Authentication Events
1. **`auth_registration`** - User account created
   - Data: username, email domain (never full email), outcome
   - Severity: info

2. **`auth_login_success`** - Successful authentication
   - Data: username, IP address, login method, MFA status
   - Severity: info
   - Note: Log the EVENT not the password or session token

3. **`auth_login_failure`** - Failed authentication attempt
   - Data: username, IP address, failure reason, throttle status
   - Severity: warning/error
   - Reason examples: "Invalid credentials", "Account locked", "Throttled"

4. **`auth_logout`** - User logged out
   - Data: username, timestamp, session duration
   - Severity: info

#### Password Management Events
5. **`auth_password_change`** - User changed their password
   - Data: username, change method (web/admin), IP address
   - Severity: info
   - Note: Log the CHANGE not the new password

6. **`auth_password_reset_request`** - Password reset requested
   - Data: username/email used in request
   - Severity: info
   - Note: Don't log success/failure to prevent enumeration

7. **`auth_password_reset_confirm`** - Password successfully reset
   - Data: username, IP where reset confirmed, timestamp
   - Severity: info

#### Authorization Events
8. **`auth_permission_change`** - User roles/permissions modified
   - Data: target username, changed permissions, admin who made change
   - Severity: warning
   - Example: "User promoted to instructor", "Courses assigned to user"

#### Security Events
9. **`security_suspicious_activity`** - Anomaly detected
   - Data: activity type, context, detection method
   - Severity: error/critical
   - Examples: Rate limit breach, impossible travel, etc.

### Data Captured for Each Event

```json
{
  "event_type": "auth_login_success",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "info",
  "username": "john_doe",
  "user_id": 123,
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "description": "User 'john_doe' logged in successfully",
  "details": {
    "login_method": "username_password",
    "mfa_used": false,
    "session_start": "2024-01-15T10:30:00Z"
  }
}
```

### What is NEVER Logged

**CRITICAL**: These items are NEVER logged, even if requested:

```python
FORBIDDEN = [
    'password',          # User passwords
    'new_password',      # New passwords during resets
    'old_password',      # Old passwords during changes
    'pwd',              # Abbreviation for password
    'secret',           # Generic secrets
    'token',            # Session/auth tokens
    'session_token',    # Session tokens
    'csrf_token',       # CSRF tokens
    'api_key',          # API keys
    'access_token',     # OAuth access tokens
    'refresh_token',    # OAuth refresh tokens
    'credentials',      # Generic credentials
]
```

The `audit_logging.py` module automatically strips these from log details.

---

## Implementation Details

### Database Schema

```python
class AuditLog(models.Model):
    # Event classification
    event_type = CharField(choices=[...])  # Indexed for queries
    timestamp = DateTimeField(auto_now_add=True)  # Indexed
    severity = CharField(choices=[info, warning, error, critical])
    
    # User context
    user = ForeignKey(User, null=True)  # May be null for pre-auth events
    username = CharField()  # Always present, indexed
    
    # Request context
    ip_address = GenericIPAddressField()  # Indexed
    user_agent = TextField()  # Device/browser info
    
    # Event details
    description = TextField()  # Human-readable summary
    details = JSONField()  # Structured data (no passwords!)
    
    class Meta:
        ordering = ['-timestamp']  # Newest first
        indexes = [
            Index(fields=['event_type', '-timestamp']),
            Index(fields=['username', '-timestamp']),
            Index(fields=['severity', '-timestamp']),
        ]
```

### Code Locations

#### Models (`models.py`)
- `AuditLog` model: Stores audit trail data
- 9 event type choices
- Multiple database indexes for query performance

#### Utilities (`audit_logging.py`)
- `log_audit_event()` - Core logging function
- `get_client_ip()` - Extract IP from request
- `get_user_agent()` - Extract user agent
- Specific logging functions for each event type:
  - `log_registration()`
  - `log_login_success()`
  - `log_login_failure()`
  - `log_logout()`
  - `log_password_change()`
  - `log_password_reset_*()` functions
  - `log_permission_change()`
- Query utilities:
  - `get_user_audit_trail()` - All events for a user
  - `get_recent_security_events()` - High-severity events
  - `get_failed_login_attempts()` - Brute-force detection
  - `get_permission_changes()` - Admin activity audit

#### Views (`views.py`)
All authentication views updated with logging calls:
- `register_view` - Logs registrations
- `login_view` - Logs successes and failures
- `logout_view` - Logs logouts
- `password_change_view` - Logs password changes
- `password_reset_request_view` - Logs reset requests
- `password_reset_confirm_view` - Logs reset confirmations
- `user_profile_edit_admin` - Logs admin changes

#### Tests (`tests_audit_logging.py`)
- 23 comprehensive tests covering:
  - Model creation and structure
  - Privacy (passwords never logged)
  - Integration with views
  - Query and filtering
  - Edge cases

---

## Usage Guide

### Basic Usage: Logging Events

```python
from .audit_logging import log_login_success

# In a view function
def login_view(request):
    # ... authentication code ...
    if user is not None:
        login(request, user)
        
        # Log successful login
        log_login_success(
            request,
            username=user.username,
            user=user,
            mfa_used=False
        )
        
        # ... rest of view ...
```

### Querying Audit Logs

```python
from .audit_logging import (
    get_user_audit_trail,
    get_failed_login_attempts,
    get_permission_changes,
    get_recent_security_events,
)

# Get all events for a user
trail = get_user_audit_trail('john_doe')
for event in trail:
    print(f"{event.timestamp}: {event.event_type}")

# Find brute-force attacks (failed logins)
failed = get_failed_login_attempts('admin', hours=24)
print(f"Failed login attempts: {failed.count()}")

# Find admin activity
changes = get_permission_changes(hours=48)

# Find security issues
security_events = get_recent_security_events(hours=24)
```

### Django Admin Integration

Add audit logs to Django admin:

```python
# In admin.py
from django.contrib import admin
from .models import AuditLog

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'username', 'ip_address', 'severity')
    list_filter = ('event_type', 'severity', 'timestamp')
    search_fields = ('username', 'ip_address', 'description')
    readonly_fields = ('timestamp', 'event_type', 'username', 'details')
    date_hierarchy = 'timestamp'
    
    def has_delete_permission(self, request):
        # Prevent deletion of audit logs
        return False
    
    def has_add_permission(self, request):
        # Prevent manual creation (only via logging functions)
        return False
```

---

## Performance Considerations

### Database Indexes

The `AuditLog` model includes optimized indexes:

```python
indexes = [
    Index(fields=['event_type', '-timestamp']),  # Query by event
    Index(fields=['username', '-timestamp']),    # Query by user
    Index(fields=['severity', '-timestamp']),    # Query by severity
]
```

These indexes enable fast queries for:
- "Show me all logins in the past 24 hours"
- "Show me all failed logins for this user"
- "Show me all critical security events"

### Query Optimization

Use `.select_related()` when joining with User model:

```python
# Fast query with single JOIN
logs = AuditLog.objects.select_related('user').filter(
    event_type='auth_login_success',
    timestamp__gte=timezone.now() - timedelta(days=1)
)

# For each log, user is already loaded (no N+1 problem)
for log in logs:
    print(f"{log.user.email}: {log.timestamp}")
```

### Disk Space

Audit logs grow at approximately:
- 1 KB per audit event (JSON details vary)
- 1000 events per busy user per month
- Growth is linear and predictable

**Recommendation**: Archive logs older than 12 months to separate storage.

---

## Privacy and Data Retention

### What Data is Stored

- **Must store**: username, IP, timestamp, event type (for accountability)
- **Should store**: User agent (device tracking), details (context)
- **Must NOT store**: passwords, tokens, secrets

### Data Retention Policy

Recommended retention by event severity:

| Severity | Retention | Reason |
|----------|-----------|--------|
| Info | 6 months | Routine events, lower compliance requirements |
| Warning | 12 months | Failed attempts, potential issues |
| Error | 24 months | Security events, require analysis |
| Critical | 36 months | Major incidents, regulatory requirements |

### GDPR Compliance

If serving EU users, audit logs contain personal data (IP addresses, usernames):

- ✅ Legal basis: Legitimate interest (security)
- ✅ Purpose: Detect and investigate misuse
- ✅ Right to erasure: Limited by audit retention requirements
- ⚠️ Consider: Anonymization after retention period expires

**Example configuration**:
```python
# Archive and anonymize old logs
from datetime import timedelta
cutoff = timezone.now() - timedelta(days=365)
old_logs = AuditLog.objects.filter(timestamp__lt=cutoff)
# Export to archive storage
# Delete from active database (if desired)
```

---

## Security Incident Response

### Investigating Suspected Compromises

When a user reports unauthorized access:

```python
from manzi.audit_logging import get_user_audit_trail

# 1. Get complete audit trail for user
trail = get_user_audit_trail('victim_user')

# 2. Look for anomalies
password_changes = trail.filter(event_type='auth_password_change')
unusual_logins = trail.filter(
    ip_address__startswith='10.0.0'  # Internal IPs only
)

# 3. Cross-reference with failed attempts
failed_logins_before = AuditLog.objects.filter(
    username='victim_user',
    event_type='auth_login_failure',
    timestamp__lt=trail[0].timestamp
).order_by('-timestamp')[:10]

# 4. Document timeline
for event in trail[:20]:  # Last 20 events
    print(f"{event.timestamp} | {event.event_type} | {event.ip_address}")
```

### Detecting Brute-Force Attacks

```python
from manzi.audit_logging import get_failed_login_attempts
from datetime import timedelta
from django.utils import timezone

# Find accounts with many failed attempts
failed_by_user = {}
thirty_minutes_ago = timezone.now() - timedelta(minutes=30)

for log in AuditLog.objects.filter(
    event_type='auth_login_failure',
    timestamp__gte=thirty_minutes_ago
):
    if log.username not in failed_by_user:
        failed_by_user[log.username] = []
    failed_by_user[log.username].append(log)

# Alert on suspicious patterns
for username, attempts in failed_by_user.items():
    if len(attempts) > 10:
        print(f"⚠️  ALERT: {len(attempts)} failed login attempts for {username}")
        # Could trigger rate limiting or account lock
```

### Finding Admin Activity

```python
from manzi.audit_logging import get_permission_changes

# Audit all admin changes
today = timezone.now().replace(hour=0, minute=0)
changes = get_permission_changes(hours=24)

for log in changes:
    print(f"Admin {log.user.username} {log.description}")
    print(f"  Target: {log.username}")
    print(f"  Changes: {log.details.get('changed_permissions')}")
    print(f"  When: {log.timestamp}")
```

---

## Best Practices

### 1. Log Early, Before State Changes

```python
# ✅ CORRECT: Log the INTENT, then execute
log_logout(request, request.user.username, user=request.user)
logout(request)  # Modify state AFTER logging

# ❌ WRONG: Log after state change (incomplete if crash occurs)
logout(request)
log_logout(request, ...)  # Never reached if logout fails
```

### 2. Include Enough Context

```python
# ✅ GOOD: Includes reason for failure
log_login_failure(
    request,
    username,
    reason="Invalid credentials",
    throttled=False
)

# ❌ POOR: No context on why failure occurred
log_audit_event(
    event_type='auth_login_failure',
    request=request,
    username=username,
    description='Failed login'
)
```

### 3. Never Trust User Input In Details

```python
# ✅ SAFE: Only log pre-validated data
log_audit_event(
    event_type='security_suspicious_activity',
    request=request,
    username=request.user.username,
    description=f"Suspicious activity: {KNOWN_ACTIVITY_TYPES[activity_type]}",
    details={'activity_type': activity_type}  # From enum, not user input
)

# ❌ DANGEROUS: User input in description
details = {}
details['user_provided_reason'] = request.GET.get('reason')  # Injection risk
```

### 4. Use Severity Appropriately

```python
# INFO: Routine operations
log_audit_event(..., severity='info')  # Normal login, password change

# WARNING: Failed security controls
log_audit_event(..., severity='warning')  # Failed login, throttled request

# ERROR: Security policy violations
log_audit_event(..., severity='error')  # Account locked, permissions changed

# CRITICAL: Active security incidents
log_audit_event(..., severity='critical')  # SQL injection attempt detected
```

### 5. Handle Failing Logs Gracefully

```python
# The audit logging functions catch exceptions and log them
# They will NOT break the main application flow if logging fails

try:
    log_audit_event(...)  # Even if this fails...
except Exception:
    logger.error("Failed to log audit event", exc_info=True)
    pass  # Application continues

# This means:
# ✅ If database is down, login still works (but not logged)
# ✅ If JSON is invalid, object still saves other attributes
# ✅ Application stays up even if logging fails
```

---

## Testing Audit Logging

### Unit Tests

Run the comprehensive test suite:

```bash
# Run all audit logging tests
python manage.py test manzi.tests_audit_logging

# Run specific test class
python manage.py test manzi.tests_audit_logging.AuditLoggingPrivacyTests

# Run with verbose output
python manage.py test manzi.tests_audit_logging -v 2
```

### Test Coverage

The `tests_audit_logging.py` suite includes:

1. **Model Tests**: Entity creation, relationships, constraints
2. **Privacy Tests**: Verify passwords/tokens/secrets never logged
3. **Integration Tests**: End-to-end authentication flow logging
4. **Query Tests**: Efficient log retrieval and filtering
5. **Security Tests**: Event type detection, severity classification

### Manual Testing

```python
from manzi.audit_logging import log_audit_event

# Test basic logging
log_audit_event(
    event_type='auth_login_success',
    request=request,
    username='testuser',
    description='Test event',
    details={'test': 'value'}
)

# Verify in Django shell
from manzi.models import AuditLog
log = AuditLog.objects.latest('timestamp')
print(log.details)  # {'test': 'value'}
```

---

## Troubleshooting

### Issue: Logs not appearing in database

**Checks**:
1. Verify migration applied: `python manage.py showmigrations manzi`
2. Check audit logging module imported: `from .audit_logging import *`
3. Verify logging function called in views
4. Check for exceptions in Django logs

### Issue: Sensitive data in audit logs

**Prevention**:
1. Never manually add to `details` dict
2. Use provided logging functions (they filter sensitive keys)
3. Pass request object (not user input) to logging
4. Review all custom logging calls for data leakage

### Issue: Audit logs consuming too much disk space

**Solutions**:
1. Archive logs older than 12 months
2. Reduce log retention period  
3. Increase index interval for cleanup tasks
4. Consider document database (MongoDB) for larger deployments

### Issue: Slow queries on audit logs

**Solutions**:
1. Verify indexes were created: `python manage.py migrate`
2. Use `.select_related()` when joining with User model
3. Filter by indexed columns first: `event_type`, `username`, `severity`, `timestamp`
4. Add database indexes for custom queries: `db_index=True` on fields

---

## Conclusion

Audit logging is a critical security practice that enables accountability, detection, and response to security incidents. This implementation provides secure, efficient, and privacy-respecting audit trailing for the DevSec Demo application.

**Key Takeaways**:
- ✅ Logs WHAT happened (event type)
- ✅ Logs WHO it happened to (username)
- ✅ Logs WHEN it happened (timestamp)
- ✅ Logs WHERE it happened (IP address)
- ✅ Logs WHY it happened (context details)
- ❌ NEVER logs secrets (passwords, tokens)
- ❌ NEVER modifies logs after creation (immutable audit trail)

For questions or improvements, see the code comments in `audit_logging.py` and the comprehensive test suite in `tests_audit_logging.py`.
