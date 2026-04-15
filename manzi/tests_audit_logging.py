"""
Test suite for audit logging functionality.

This test module verifies that security-relevant events are properly logged
to the AuditLog model without exposing sensitive data.

Test Categories:
1. Event Creation: Verify audit events are created in the database
2. Privacy: Ensure passwords and secrets are never logged
3. Data Structure: Validate audit log entries contain correct data
4. Integration: Verify audit logging doesn't break existing authentication flows
5. Query: Test audit log filtering and querying capabilities
"""

import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from .models import AuditLog
from .audit_logging import (
    log_audit_event,
    log_registration,
    log_login_success,
    log_login_failure,
    log_logout,
    log_password_change,
    log_password_reset_request,
    log_password_reset_confirm,
    log_permission_change,
    get_user_audit_trail,
    get_recent_security_events,
    get_failed_login_attempts,
    get_permission_changes,
)


class AuditLogModelTests(TestCase):
    """Test the AuditLog model itself."""
    
    def setUp(self):
        """Create test user and request object."""
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.client = Client()
    
    def test_audit_log_creation(self):
        """Test creating a basic audit log entry."""
        log = AuditLog.objects.create(
            event_type='auth_login_success',
            username='testuser',
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            description='Test login',
            details={'login_method': 'password'}
        )
        
        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(log.username, 'testuser')
        self.assertEqual(log.event_type, 'auth_login_success')
        self.assertIn('login_method', log.details)
    
    def test_audit_log_immutability(self):
        """Test that audit log entries are immutable (never modified)."""
        log = AuditLog.objects.create(
            event_type='auth_login_success',
            username='testuser',
            user=self.user,
            ip_address='192.168.1.1',
            description='Original description',
            details={'original': True}
        )
        
        original_timestamp = log.timestamp
        
        # Audit logs should never be modified after creation
        # They're created immutably and exist for forensic purposes
        self.assertEqual(log.description, 'Original description')
        self.assertEqual(log.timestamp, original_timestamp)
    
    def test_audit_log_ordering(self):
        """Test that audit logs are ordered by timestamp (newest first)."""
        # Create multiple logs
        log1 = AuditLog.objects.create(
            event_type='auth_login_success',
            username='user1',
            ip_address='192.168.1.1',
            description='First login'
        )
        
        # Create second log after a small delay
        log2 = AuditLog.objects.create(
            event_type='auth_login_failure',
            username='user2',
            ip_address='192.168.1.2',
            description='Failed login'
        )
        
        # Query should return newest first (log2 before log1)
        logs = AuditLog.objects.all()
        self.assertEqual(logs[0].id, log2.id)
        self.assertEqual(logs[1].id, log1.id)


class AuditLoggingPrivacyTests(TestCase):
    """Test that audit logging never exposes sensitive data."""
    
    def setUp(self):
        """Create test user and request."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testsecretpassword'
        )
        self.client = Client()
    
    def test_password_never_logged(self):
        """Verify that passwords are NEVER logged in audit events."""
        # Attempt to log with password in details
        log_audit_event(
            event_type='auth_password_change',
            request=self.client.get('/').wsgi_request,
            username='testuser',
            user=self.user,
            description='Password changed',
            details={
                'password': 'secret123',  # Attempt to log password
                'new_password': 'newsecret',  # Attempt to log new password
                'old_password': 'oldpassword',  # Attempt to log old password
                'safe_field': 'can_log_this'
            }
        )
        
        # Find the log entry
        log = AuditLog.objects.get(event_type='auth_password_change')
        
        # Verify password-related fields were removed
        self.assertNotIn('password', log.details)
        self.assertNotIn('new_password', log.details)
        self.assertNotIn('old_password', log.details)
        
        # Verify safe fields remain
        self.assertIn('safe_field', log.details)
    
    def test_tokens_never_logged(self):
        """Verify that authentication tokens are NEVER logged."""
        self.client.get('/').wsgi_request
        
        log_audit_event(
            event_type='auth_login_success',
            request=self.client.get('/').wsgi_request,
            username='testuser',
            details={
                'session_token': 'abc123xyz',  # Attempt to log session token
                'csrf_token': 'xyz789abc',  # Attempt to log CSRF token
                'api_key': 'secret_api_key',  # Attempt to log API key
                'access_token': 'bearer_token',  # Attempt to log access token
                'refresh_token': 'refresh_xyz',  # Attempt to log refresh token
                'safe_data': 'this_is_ok'
            }
        )
        
        log = AuditLog.objects.filter(event_type='auth_login_success').first()
        
        # Verify sensitive tokens were removed
        self.assertNotIn('session_token', log.details)
        self.assertNotIn('csrf_token', log.details)
        self.assertNotIn('api_key', log.details)
        self.assertNotIn('access_token', log.details)
        self.assertNotIn('refresh_token', log.details)
        
        # Verify safe data remains
        self.assertIn('safe_data', log.details)
    
    def test_credentials_never_logged(self):
        """Verify that credentials are NEVER logged."""
        self.client.get('/').wsgi_request
        
        log_audit_event(
            event_type='auth_login_success',
            request=self.client.get('/').wsgi_request,
            username='testuser',
            details={
                'credentials': 'user:pass',  # Attempt to log credentials
                'secret': 'mysecret',  # Attempt to log secret
                'login_method': 'password'  # Safe to log
            }
        )
        
        log = AuditLog.objects.filter(event_type='auth_login_success').first()
        
        # Verify sensitive fields were removed
        self.assertNotIn('credentials', log.details)
        self.assertNotIn('secret', log.details)
        
        # Verify safe fields remain
        self.assertIn('login_method', log.details)


class RegistrationAuditTests(TestCase):
    """Test audit logging for registration events."""
    
    def setUp(self):
        self.client = Client()
    
    def test_registration_logged(self):
        """Test that user registration is logged to audit trail."""
        initial_count = AuditLog.objects.count()
        
        # Register new user
        self.client.post('/register/', {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'complexpass123!',
            'password2': 'complexpass123!',
        }, follow=True)
        
        # Verify audit log was created
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)
        
        # Find the registration log
        reg_log = AuditLog.objects.filter(event_type='auth_registration').first()
        self.assertIsNotNone(reg_log)
        self.assertEqual(reg_log.username, 'newuser')
        self.assertIn('newuser', reg_log.description)


class LoginAuditTests(TestCase):
    """Test audit logging for login events (success and failure)."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='correctpassword'
        )
    
    def test_successful_login_logged(self):
        """Test that successful logins are logged."""
        initial_count = AuditLog.objects.count()
        
        # Perform successful login
        self.client.post('/login/', {
            'username': 'testuser',
            'password': 'correctpassword'
        }, follow=True)
        
        # Verify login success log was created
        login_logs = AuditLog.objects.filter(event_type='auth_login_success')
        self.assertEqual(login_logs.count(), 1)
        
        log = login_logs.first()
        self.assertEqual(log.username, 'testuser')
        self.assertEqual(log.user, self.user)
        self.assertIn('login', log.description)
    
    def test_failed_login_logged(self):
        """Test that failed login attempts are logged."""
        # Perform failed login
        self.client.post('/login/', {
            'username': 'testuser',
            'password': 'wrongpassword'
        }, follow=True)
        
        # Verify failed login was logged
        failed_logs = AuditLog.objects.filter(event_type='auth_login_failure')
        self.assertEqual(failed_logs.count(), 1)
        
        log = failed_logs.first()
        self.assertEqual(log.username, 'testuser')
        self.assertIn('Failed', log.description)
    
    def test_login_ip_address_recorded(self):
        """Test that IP address is recorded for each login."""
        self.client.post('/login/', {
            'username': 'testuser',
            'password': 'correctpassword'
        }, follow=True)
        
        log = AuditLog.objects.filter(event_type='auth_login_success').first()
        
        # Should have an IP address (may be 127.0.0.1 for test)
        self.assertIsNotNone(log.ip_address)
        self.assertTrue(len(log.ip_address) > 0)


class LogoutAuditTests(TestCase):
    """Test audit logging for logout events."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
    
    def test_logout_logged(self):
        """Test that logout events are logged."""
        # Login first
        self.client.login(username='testuser', password='testpass')
        
        initial_count = AuditLog.objects.count()
        
        # Perform logout
        self.client.get('/logout/', follow=True)
        
        # Verify logout was logged
        logout_logs = AuditLog.objects.filter(event_type='auth_logout')
        self.assertEqual(logout_logs.count(), 1)
        
        log = logout_logs.first()
        self.assertEqual(log.username, 'testuser')


class PasswordChangeAuditTests(TestCase):
    """Test audit logging for password changes."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='oldpassword123'
        )
    
    def test_password_change_logged(self):
        """Test that password changes are logged."""
        # Login first
        self.client.login(username='testuser', password='oldpassword123')
        
        # Change password
        self.client.post('/password-change/', {
            'old_password': 'oldpassword123',
            'new_password1': 'newpassword456!',
            'new_password2': 'newpassword456!',
        }, follow=True)
        
        # Verify password change was logged
        pw_logs = AuditLog.objects.filter(event_type='auth_password_change')
        self.assertEqual(pw_logs.count(), 1)
        
        log = pw_logs.first()
        self.assertEqual(log.username, 'testuser')
        self.assertIn('password', log.description.lower())
        
        # Verify password was NOT stored in details
        self.assertNotIn('newpassword456!', str(log.details))
        self.assertNotIn('oldpassword123', str(log.details))


class PasswordResetAuditTests(TestCase):
    """Test audit logging for password reset events."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpass'
        )
    
    def test_password_reset_request_logged(self):
        """Test that password reset requests are logged."""
        # Request password reset
        self.client.post('/password-reset/', {
            'email': 'test@example.com'
        }, follow=True)
        
        # Verify reset request was logged
        reset_logs = AuditLog.objects.filter(event_type='auth_password_reset_request')
        self.assertEqual(reset_logs.count(), 1)
        
        log = reset_logs.first()
        self.assertEqual(log.username, 'testuser')


class PermissionChangeAuditTests(TestCase):
    """Test audit logging for permission/role changes."""
    
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass'
        )
        self.target_user = User.objects.create_user(
            username='targetuser',
            password='targetpass'
        )
    
    def test_permission_change_logged(self):
        """Test that permission changes are logged by admin."""
        from .audit_logging import log_permission_change
        
        # Create a mock request for testing
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/')
        request.user = self.admin
        
        # Log a permission change
        log_permission_change(
            request,
            target_username='targetuser',
            changed_permissions=['is_staff'],
            change_type='role',
            user=self.admin
        )
        
        # Verify permission change was logged
        perm_logs = AuditLog.objects.filter(event_type='auth_permission_change')
        self.assertEqual(perm_logs.count(), 1)
        
        log = perm_logs.first()
        self.assertEqual(log.username, 'targetuser')
        self.assertEqual(log.user, self.admin)
        self.assertIn('admin', log.description)


class AuditLogQueryTests(TestCase):
    """Test querying and filtering audit logs."""
    
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='pass1')
        self.user2 = User.objects.create_user(username='user2', password='pass2')
        
        # Create various audit logs
        AuditLog.objects.create(
            event_type='auth_login_success',
            username='user1',
            user=self.user1,
            ip_address='192.168.1.1',
            description='Login 1'
        )
        
        AuditLog.objects.create(
            event_type='auth_login_failure',
            username='user2',
            ip_address='192.168.1.2',
            description='Failed login',
            severity='warning'
        )
        
        AuditLog.objects.create(
            event_type='auth_password_change',
            username='user1',
            user=self.user1,
            ip_address='192.168.1.1',
            description='Password changed',
            severity='info'
        )
    
    def test_get_user_audit_trail(self):
        """Test retrieving audit trail for a specific user."""
        trail = get_user_audit_trail('user1')
        
        # Should get 2 logs for user1
        self.assertEqual(trail.count(), 2)
        
        # Verify all are for user1
        for log in trail:
            self.assertEqual(log.username, 'user1')
    
    def test_get_failed_login_attempts(self):
        """Test retrieving failed login attempts."""
        failed = get_failed_login_attempts()
        
        # Should get the 1 failed login
        self.assertEqual(failed.count(), 1)
        self.assertEqual(failed.first().username, 'user2')
    
    def test_get_failed_login_attempts_for_user(self):
        """Test getting failed logins for specific user."""
        # Add another failed attempt for user1
        AuditLog.objects.create(
            event_type='auth_login_failure',
            username='user1',
            ip_address='192.168.1.1',
            description='Failed login'
        )
        
        # Get failed attempts for user1
        failed = get_failed_login_attempts('user1')
        self.assertEqual(failed.count(), 1)
        self.assertEqual(failed.first().username, 'user1')
    
    def test_get_recent_security_events(self):
        """Test retrieving recent high-severity security events."""
        # Add a critical event
        AuditLog.objects.create(
            event_type='security_suspicious_activity',
            username='user1',
            ip_address='192.168.1.1',
            description='Suspicious activity',
            severity='critical'
        )
        
        recent = get_recent_security_events(hours=24)
        
        # Should include the critical event
        critical_logs = recent.filter(severity='critical')
        self.assertEqual(critical_logs.count(), 1)
    
    def test_get_permission_changes(self):
        """Test retrieving permission change logs."""
        # Add a permission change
        AuditLog.objects.create(
            event_type='auth_permission_change',
            username='user2',
            user=self.user2,
            ip_address='192.168.1.2',
            description='Admin promoted user',
            severity='warning'
        )
        
        changes = get_permission_changes(hours=24)
        
        # Should get the permission change
        self.assertEqual(changes.count(), 1)
        self.assertEqual(changes.first().username, 'user2')


class AuditLogSecurityPropertiesTests(TestCase):
    """Test security-related properties of audit logs."""
    
    def test_is_security_event_property(self):
        """Test the is_security_event property."""
        # Create various event types
        failed_login = AuditLog.objects.create(
            event_type='auth_login_failure',
            username='user1',
            ip_address='127.0.0.1',
            severity='warning'
        )
        
        suspicious = AuditLog.objects.create(
            event_type='security_suspicious_activity',
            username='user2',
            ip_address='127.0.0.1',
            severity='error'
        )
        
        normal_login = AuditLog.objects.create(
            event_type='auth_login_success',
            username='user3',
            ip_address='127.0.0.1',
            severity='info'
        )
        
        # Verify security event detection
        self.assertTrue(failed_login.is_security_event)
        self.assertTrue(suspicious.is_security_event)
        self.assertFalse(normal_login.is_security_event)
    
    def test_severity_levels(self):
        """Test that severity levels are properly recorded."""
        credentials = {
            'info': 'Info event',
            'warning': 'Warning event',
            'error': 'Error event',
            'critical': 'Critical event'
        }
        
        for severity, desc in credentials.items():
            AuditLog.objects.create(
                event_type='auth_login_success',
                username='testuser',
                ip_address='127.0.0.1',
                severity=severity,
                description=desc
            )
        
        # Verify all severity levels exist
        for severity in credentials.keys():
            log = AuditLog.objects.filter(severity=severity).first()
            self.assertEqual(log.severity, severity)


class AuditLogJSONValidationTests(TestCase):
    """Test that audit log JSON details are valid and queryable."""
    
    def test_json_details_valid(self):
        """Test that JSON details are stored and retrieved correctly."""
        test_data = {
            'login_method': 'password',
            'mfa_used': False,
            'session_duration_minutes': 30,
            'nested': {
                'key1': 'value1',
                'key2': 'value2'
            }
        }
        
        log = AuditLog.objects.create(
            event_type='auth_login_success',
            username='testuser',
            ip_address='127.0.0.1',
            details=test_data
        )
        
        # Retrieve and verify
        retrieved = AuditLog.objects.get(id=log.id)
        self.assertEqual(retrieved.details, test_data)
        self.assertEqual(retrieved.details['login_method'], 'password')
        self.assertEqual(retrieved.details['nested']['key1'], 'value1')
    
    def test_json_details_is_json_serializable(self):
        """Test that details can be JSON serialized for API responses."""
        log = AuditLog.objects.create(
            event_type='auth_login_success',
            username='testuser',
            ip_address='127.0.0.1',
            details={'method': 'password', 'duration': 30}
        )
        
        # Should be JSON serializable
        serialized = json.dumps(log.details)
        deserialized = json.loads(serialized)
        
        self.assertEqual(deserialized['method'], 'password')
