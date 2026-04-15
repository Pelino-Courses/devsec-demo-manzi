# Brute-Force Protection: Design & Implementation

## Overview

This document describes the brute-force protection implementation in the MANZI authentication system. It protects the login endpoint against credential-based attacks while maintaining usability for legitimate users.

## The Brute-Force Attack

### What Is Brute-Force?

A brute-force attack is when an attacker systematically tries many credential combinations against a login endpoint:

```
attack.py:
    for password in common_passwords:
        login_attempt('admin', password)  # Try 10,000 passwords/second
```

**Real-World Attack Scenario:**
1. Attacker obtains username "admin" from public sources
2. Attacker writes script to try 1 million common passwords
3. Without protection: 1 million attempts in ~100 seconds
4. **Problem**: Attacker finds password if it's in compromise list

### Attack Methods

**Account-Targeted Attack:**
- Attacker focuses on one user (e.g., admin, ceo@company.com)
- Goal: Break into specific high-value account
- Defense: Account-based throttling

**Distributed Attack:**
- Attacker uses many IPs or botnets
- Each IP only tries a few passwords (stays under limits)
- Goal: Evade per-IP rate limits
- Defense: IP-based throttling + account lockout

**Hybrid Attack:**
- Attacker tries many usernames from few IPs
- Goal: Find valid accounts then brute-force passwords
- Defense: Hybrid method combining both approaches

### Impact Without Protection

- **Account Compromise**: Weak passwords broken in seconds
- **Spray Attacks**: Try password "Password123" for all 1000 accounts
- **Credential Stuffing**: Use leaked passwords from other sites
- **Service Disruption**: Attacker fills logs, exhausts resources

## Prevention Strategy - Hybrid Throttling

MANZI implements **hybrid throttling** combining account and IP-based limits:

### Architecture

```
Login Request → Get Client IP → Check Throttling → Allow/Block
                                        ↓
                    ┌────────────────────┬────────────────────┐
                    ↓                    ↓                    ↓
            Account-Based Check   IP-Based Check      Time Window Check
            (same user, many IPs) (many users, same IP) (15 minute window)
                    ↓                    ↓                    ↓
            3 failures = slow     5+ failures = throttle  Old attempts
            5 failures = lockout  per all users from IP   don't count
```

### Layer 1: Account-Based Throttling

Tracks failed attempts **by username** regardless of IP:

```python
# Protection against: Account-targeted brute-force
# Scenario: Attacker tries 1000 IPs for 'admin' account

# 1st attempt:   ALLOWED   (0 failures)
# 2nd attempt:   ALLOWED   (1 failure)
# 3rd attempt:   ALLOWED   (2 failures)
# 4th attempt:   THROTTLED (3+ failures → exponential backoff)
#    └─ Wait 8 seconds
# 5th attempt (after wait):  ALLOWED (if password correct, failures reset)
# 6th attempt (wrong pass):  LOCKOUT (5 failures → 5 min lockout)
```

**Exponential Backoff:** 2s, 4s, 8s, 16s, 32s... (doubles each time)

### Layer 2: IP-Based Throttling

Tracks failed attempts **by IP address** for ALL usernames:

```python
# Protection against: Distributed/spray attacks
# Scenario: Attacker uses proxy to try 100 usernames from 1 IP

# Attempt 1 (user1, IP):     ALLOWED
# Attempt 2 (user2, IP):     ALLOWED
# Attempt 3 (user3, IP):     ALLOWED
# ...
# Attempt 6+ (userN, IP):    THROTTLED (>3 failures from this IP)
```

**Use Case**: Blocks "spray attacks" trying password "Password123" on many accounts

### Layer 3: Time Window

Failed attempts only count within 15-minute window:

```python
# If attacker's last attempt was 16 minutes ago → counter resets
# Benefit: Allows slowdown without permanent ban

ATTEMPT_WINDOW_MINUTES = 15
```

**UX Implication**: User can retry every 15 minutes without doing anything

## Configuration

All throttling parameters are defined in `brute_force_protection.py`:

```python
BRUTE_FORCE_CONFIG = {
    # Trigger slowdown after N failures
    'FAILED_ATTEMPTS_THRESHOLD': 3,
    
    # Trigger hard lockout after N failures
    'LOCKOUT_THRESHOLD': 5,
    
    # Base cooldown seconds (doubles with each attempt)
    'BASE_COOLDOWN_SECONDS': 2,
    
    # How long to lock account
    'LOCKOUT_DURATION_SECONDS': 300,  # 5 minutes
    
    # How far back to check attempts
    'ATTEMPT_WINDOW_MINUTES': 15,
}
```

### Tuning the Protection

**For High-Security Environments:**
```python
FAILED_ATTEMPTS_THRESHOLD = 2    # Faster slowdown
LOCKOUT_THRESHOLD = 3             # Faster lockout
LOCKOUT_DURATION_SECONDS = 600   # 10 min lockout
```

**For User-Friendly Environments:**
```python
FAILED_ATTEMPTS_THRESHOLD = 5    # More attempts allowed
LOCKOUT_THRESHOLD = 10           # More tolerant
LOCKOUT_DURATION_SECONDS = 180   # 3 min lockout
```

## Implementation Details

### 1. Database Model: LoginAttempt

```python
class LoginAttempt(models.Model):
    username = models.CharField(max_length=150)  # Username (not FK, allows tracking before account exists)
    ip_address = models.GenericIPAddressField()  # Where attempt came from
    attempt_type = models.CharField(choices=[('failed', ...), ('success', ...)])
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField()  # Device/browser info for analysis
```

**Why not use user FK?**
- Allows tracking attempts before/without valid account
- Tracks brute-force even if username doesn't exist
- More complete audit trail

### 2. Throttling Check Function

```python
def is_login_throttled(username, ip_address):
    """Returns (is_throttled, reason, cooldown_seconds)"""
    
    # Check account failures
    user_failures = get_recent_failed_attempts(username).count()
    
    # Hard lockout if too many
    if user_failures >= 5:
        return True, 'Account locked', 300
    
    # Slowdown if many failures
    if user_failures >= 3:
        return True, f'Please wait {cooldown} seconds', cooldown
    
    # Check IP failures (against all usernames)
    ip_failures = LoginAttempt.objects.filter(
        ip_address=ip_address,
        attempt_type='failed',
        timestamp__gte=15_min_ago
    ).count()
    
    if ip_failures >= 5:
        return True, 'Too many attempts from your IP', cooldown
    
    return False, '', 0
```

### 3. Modified Login View

```python
@anonymous_only
def login_view(request):
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form_data = request.POST
        
        # STEP 1: Check throttling BEFORE checking credentials
        is_throttled, reason, wait_time = is_login_throttled(
            username, client_ip
        )
        
        if is_throttled:
            messages.error(request, 'Too many login attempts')
            record_login_attempt(username, client_ip, request, success=False)
            return render(request, 'login.html', {'form': form})
        
        # STEP 2: Check credentials normally
        user = authenticate(request, username, password)
        
        if user:
            # STEP 3: Success - clear failed attempts
            clear_login_attempts(username)
            record_login_attempt(username, client_ip, request, success=True)
            login(request, user)
            return redirect('dashboard')
        else:
            # STEP 4: Failure - record attempt
            record_login_attempt(username, client_ip, request, success=False)
            messages.error(request, 'Invalid credentials')
            return render(request, 'login.html', {'form': form})
```

## Security Analysis

### Threats Mitigated

✅ **Brute-Force Attack**: Exponential backoff makes password guessing impractical
```
1 attempt: instant
3 failures: 8 sec wait (8 total to try 3 passwords)
5 failures: LOCKOUT (5 min = 18000 sec to try)

For 10,000 passwords: 18000 * 10000 = 180M seconds = 5.7 YEARS
```

✅ **Distributed Attack**: IP-based throttling catches spray attacks

✅ **Information Leakage**: Generic error messages ("Too many attempts")
- Doesn't say "account locked" vs "too many IPs"
- Doesn't reveal if username exists

✅ **Database Exhaustion**: Automatic cleanup of old attempts (>30 days)

### Known Limitations

⚠️ **Shared IP Networks**: 
- Corporate networks share IP
- VPN/Proxy users might have same IP as attacker
- **Mitigation**: Cooldown is only 5 min; legit users can retry

⚠️ **Distributed via Botnets**:
- Each botnet node sends from different IP
- Might not trigger IP-based throttling if enough nodes
- **Mitigation**: Account-based threshold still prevents brute-force, just slower

⚠️ **Account Enumeration**:
- While throttling is generic, failed attempts are recorded
- **Mitigation**: This is acceptable - we want audit trail; enumeration is lower priority than brute-force

### Security vs Usability Trade-offs

| Scenario | Throttling | UX Impact | Decision |
|----------|-----------|----------|----------|
| Legit user wrong password | 1 attempt allowed | Minimal - can retry immediately | ✅ Good |
| Legit user repeated typos | 3 attempts, then slowdown | Waits 8 sec between attempts | ✅ Acceptable |
| Legit user account lockout | After 5 attempts over 15min | Can retry after 5 min | ✅ Fair |
| Attacker with 1000 IPs | Account-based lockout still applies | Cannot break account | ✅ Secure |
| Corporate network spam | IP throttling kicks in | Can wait 15 min, counter resets | ⚠️ Slightly annoying |

**Conclusion**: Prioritizes security over maximum convenience - acceptable for auth

## Testing

Comprehensive test suite in `tests_brute_force.py` covers:

### Normal Cases
- First login not throttled
- Successful login clears attempts
- Legitimate retry after cooldown works

### Security Cases
- Throttling after threshold
- Account lockout after max failures
- IP-based throttling detects spray attacks
- Exponential backoff increases with failures
- Generic error messages don't leak info
- Hybrid protection (account + IP) works together

### Edge Cases
- Time window expiration (15 min)
- Different IPs for same user
- X-Forwarded-For header handling
- Old attempts cleaned up (>30 days)

**Run tests:**
```bash
python manage.py test manzi.tests_brute_force -v 2
```

## Monitoring

### Admin Interface

Access `/admin/manzi/loginattempt/` to:
- View all login attempts (failed & successful)
- Filter by username, IP, attempt type, date
- Monitor for suspicious patterns

### Suspicious Patterns to Watch

```
// Red flag 1: Rapid failed attempts from one IP
SELECT COUNT(*) FROM manzi_loginattempt
WHERE attempt_type='failed' AND timestamp > NOW() - INTERVAL 5 MINUTE
GROUP BY ip_address HAVING COUNT(*) > 20

// Red flag 2: Failed attempts on many usernames from one IP (spray)
SELECT COUNT(DISTINCT username) FROM manzi_loginattempt
WHERE attempt_type='failed' AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY ip_address HAVING COUNT(DISTINCT username) > 10

// Red flag 3: Successful login after many failures (possible compromise)
SELECT username, COUNT(*) as failures FROM manzi_loginattempt
WHERE attempt_type='failed'
GROUP BY username HAVING COUNT(*) > 10
```

## Configuration in Django Settings

If needed, override defaults in `settings.py`:

```python
# Override brute-force config
from manzi.brute_force_protection import update_config

update_config({
    'FAILED_ATTEMPTS_THRESHOLD': 5,
    'LOCKOUT_THRESHOLD': 10,
    'LOCKOUT_DURATION_SECONDS': 600,
})
```

## Deployment Considerations

### Before Going Live

1. **Test with real IPs**: Verify X-Forwarded-For handling if behind proxy
2. **Monitor for false positives**: Check if legit users are getting blocked
3. **Set up admin alerts**: Get notified of suspicious patterns
4. **Backup rate limits**: Have DB cleanup scheduled

### Performance

- **Database Indexes**: LoginAttempt has indexes on username, IP, timestamp
- **Query Efficiency**: `is_login_throttled()` uses efficient queries
- **Cleanup Task**: Schedule daily cleanup of old attempts:

```python
# management/commands/cleanup_login_attempts.py
from django.core.management.base import BaseCommand
from manzi.brute_force_protection import cleanup_old_attempts

class Command(BaseCommand):
    def handle(self, *args, **options):
        deleted = cleanup_old_attempts(days=30)
        self.stdout.write(f'Deleted {deleted} old login attempts')
```

Schedule with cron:
```bash
0 2 * * * python /path/to/manage.py cleanup_login_attempts
```

## Future Improvements

Potential enhancements to consider:

1. **CAPTCHA After Threshold**: Show CAPTCHA instead of blocking
2. **Email Notification**: Alert user if their account is being attacked
3. **Geographic Anomaly**: Flag logins from unusual locations
4. **Pattern Learning**: Detect advanced attacks via ML
5. **OTP Backup**: Offer OTP as additional auth factor
6. **Honeypot Fields**: Detect bots with hidden form fields

## Conclusion

This brute-force protection provides:
- ✅ Multi-layered defense (account + IP)
- ✅ Progressive penalties (exponential backoff)
- ✅ Hard lockout for repeated failures
- ✅ Legitimate user consideration (15 min window, 5 min lockout)
- ✅ Audit trail (all attempts logged)
- ✅ Admin monitoring (can inspect attempts)
- ✅ Auditable and testable (clear logic, comprehensive tests)

The system balances **security** (prevents brute-force effectively) with **usability** (doesn't permanently lock out legitimate users).
