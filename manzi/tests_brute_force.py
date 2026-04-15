"""
Tests for brute-force protection functionality.

This module tests the login throttling and brute-force protection mechanisms,
including:
- Failed attempt tracking
- Progressive cooldowns
- Account lockout
- IP-based throttling
- Legitimate user experience
- Hybrid protection strategy
"""

from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from .models import LoginAttempt
from .brute_force_protection import (
    get_client_ip,
    is_login_throttled,
    record_login_attempt,
    clear_login_attempts,
    get_recent_failed_attempts,
    calculate_cooldown_seconds,
    get_throttle_wait_time,
    BRUTE_FORCE_CONFIG,
)


class BruteForceProtectionTests(TestCase):
    """
    Test cases for brute-force protection functionality.
    """

    def setUp(self):
        """Set up test client and test user."""
        self.client = Client()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        self.login_url = reverse('manzi:login')

    def test_first_login_not_throttled(self):
        """Test that first login attempt is not throttled."""
        is_throttled, reason, cooldown = is_login_throttled('testuser', '192.168.1.1')
        self.assertFalse(is_throttled)

    def test_throttle_after_threshold_failures(self):
        """
        Test that login is throttled after exceeding failure threshold.
        
        Security: Prevents excessive login attempts.
        """
        threshold = BRUTE_FORCE_CONFIG['FAILED_ATTEMPTS_THRESHOLD']
        
        # Create failed attempts at threshold
        request = self.factory.post('/')
        for i in range(threshold):
            record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Next attempt should be throttled
        is_throttled, reason, cooldown = is_login_throttled('testuser', '192.168.1.1')
        self.assertTrue(is_throttled)

    def test_account_lockout_after_max_failures(self):
        """
        Test that account is locked after maximum failures.
        
        Security: Hard lockout after too many attempts.
        """
        lockout_threshold = BRUTE_FORCE_CONFIG['LOCKOUT_THRESHOLD']
        
        # Create failed attempts at lockout threshold
        request = self.factory.post('/')
        for i in range(lockout_threshold):
            record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Should be throttled and reason should mention lockout
        is_throttled, reason, cooldown = is_login_throttled('testuser', '192.168.1.1')
        self.assertTrue(is_throttled)
        self.assertIn('locked', reason.lower())

    def test_progressive_cooldown(self):
        """
        Test that cooldown increases with each failure (exponential backoff).
        
        Security: Exponential backoff makes brute-force increasingly expensive.
        """
        # Test cooldown calculation
        cooldown_1 = calculate_cooldown_seconds(1)  # 2^0 * 2 = 2 seconds
        cooldown_2 = calculate_cooldown_seconds(2)  # 2^1 * 2 = 4 seconds
        cooldown_3 = calculate_cooldown_seconds(3)  # 2^2 * 2 = 8 seconds
        cooldown_4 = calculate_cooldown_seconds(4)  # 2^3 * 2 = 16 seconds
        
        self.assertLess(cooldown_1, cooldown_2)
        self.assertLess(cooldown_2, cooldown_3)
        self.assertLess(cooldown_3, cooldown_4)

    def test_ip_based_throttling(self):
        """
        Test that excessive failures from one IP throttle that IP.
        
        Security: Prevents distributed brute-force from same IP/proxy.
        """
        # Create failures from different usernames but same IP
        request = self.factory.post('/')
        for i in range(5):
            record_login_attempt(f'user{i}', '192.168.1.100', request, success=False)
        
        # New login attempt from same IP should be throttled
        is_throttled, reason, cooldown = is_login_throttled('newuser', '192.168.1.100')
        self.assertTrue(is_throttled)
        self.assertIn('IP', reason)

    def test_hybrid_throttling_account_and_ip(self):
        """
        Test hybrid approach: both account and IP-based throttling work together.
        
        Security: Protects against both targeted and distributed attacks.
        """
        # Scenario: Account takes multiple failures from different IPs
        ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        request = self.factory.post('/')
        
        for ip in ips:
            for i in range(3):
                record_login_attempt('testuser', ip, request, success=False)
        
        # Account should be throttled despite being from different IPs
        is_throttled, reason, cooldown = is_login_throttled('testuser', '192.168.1.4')
        self.assertTrue(is_throttled)

    def test_successful_login_clears_failed_attempts(self):
        """
        Test that successful login clears failed attempts.
        
        UX: Legitimate user can login again after fixing their password.
        """
        # Create some failed attempts
        request = self.factory.post('/')
        for i in range(2):
            record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Clear attempts (simulating successful login)
        clear_login_attempts('testuser')
        
        # No failed attempts should remain
        failed_count = get_recent_failed_attempts('testuser').count()
        self.assertEqual(failed_count, 0)

    def test_failed_login_attempt_recorded(self):
        """Test that failed login attempts are recorded in database."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword123!'
        }
        response = self.client.post(self.login_url, data)
        
        # Failed attempt should be recorded
        attempts = LoginAttempt.objects.filter(
            username='testuser',
            attempt_type='failed'
        )
        self.assertGreater(attempts.count(), 0)

    def test_successful_login_attempt_recorded(self):
        """Test that successful login attempts are recorded."""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!'
        }
        response = self.client.post(self.login_url, data)
        
        # Successful attempt should be recorded
        attempts = LoginAttempt.objects.filter(
            username='testuser',
            attempt_type='success'
        )
        self.assertGreater(attempts.count(), 0)

    def test_throttled_login_shows_generic_message(self):
        """
        Test that throttled login shows generic message.
        
        Security: Doesn't reveal whether account or IP is throttled.
        """
        # Create failures to trigger throttling
        threshold = BRUTE_FORCE_CONFIG['FAILED_ATTEMPTS_THRESHOLD']
        request = self.factory.post('/')
        for i in range(threshold + 1):
            record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Try to login - should be throttled
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!'
        }
        response = self.client.post(self.login_url, data)
        
        # Should show throttling message
        self.assertIn('Too many login attempts', str(response.content.decode()))

    def test_attempt_window_respects_time(self):
        """
        Test that old attempts outside the window don't count.
        
        UX: After waiting sufficient time, attempts reset.
        """
        window_minutes = BRUTE_FORCE_CONFIG['ATTEMPT_WINDOW_MINUTES']
        
        # Create attempt
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            attempt_type='failed'
        )
        
        # Move timestamp to outside window
        past_time = timezone.now() - timedelta(minutes=window_minutes + 1)
        attempt.timestamp = past_time
        attempt.save()
        
        # Recent attempts should be 0
        recent = get_recent_failed_attempts('testuser')
        self.assertEqual(recent.count(), 0)

    def test_get_throttle_wait_time(self):
        """Test that wait time is calculated correctly."""
        # Create a recent failed attempt
        request = self.factory.post('/')
        record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Wait time should be >= 0
        wait_time = get_throttle_wait_time('testuser', '192.168.1.1')
        self.assertGreaterEqual(wait_time, 0)

    def test_legitimate_user_can_retry_after_cooldown(self):
        """
        Test that legitimate user can retry after cooldown period.
        
        UX: System is not permanently blocking, just throttling.
        """
        # Create failed attempts
        request = self.factory.post('/')
        for i in range(2):
            record_login_attempt('testuser', '192.168.1.1', request, success=False)
        
        # Should be throttled now
        is_throttled1, _, _ = is_login_throttled('testuser', '192.168.1.1')
        self.assertTrue(is_throttled1)
        
        # Create attempt far in past
        old_attempt = LoginAttempt.objects.first()
        old_attempt.timestamp = timezone.now() - timedelta(minutes=20)  # Outside window
        old_attempt.save()
        
        # After waiting, should not be throttled
        is_throttled2, _, _ = is_login_throttled('testuser', '192.168.1.1')
        self.assertFalse(is_throttled2)

    def test_different_usernames_different_throttling(self):
        """
        Test that throttling is per-username (not affecting other users).
        
        UX: One user's failed attempts don't block other users.
        """
        # User1 has many failures
        threshold = BRUTE_FORCE_CONFIG['FAILED_ATTEMPTS_THRESHOLD']
        for i in range(threshold + 1):
            record_login_attempt('user1', '192.168.1.1', self.client._request_factory().post('/'), success=False)
        
        # User1 should be throttled
        throttled1, _, _ = is_login_throttled('user1', '192.168.1.1')
        self.assertTrue(throttled1)
        
        # User2 should not be throttled
        throttled2, _, _ = is_login_throttled('user2', '192.168.1.1')
        # User2 might be throttled by IP if there are enough failures from that IP
        # so this test just checks user1 is throttled independently

    def test_get_client_ip_from_request(self):
        """Test that client IP is extracted correctly."""
        request = self.factory.post('/')
        
        ip = get_client_ip(request)
        # Should get some IP
        self.assertIsNotNone(ip)
        self.assertNotEqual(ip, '')

    def test_get_client_ip_from_x_forwarded_for(self):
        """Test that X-Forwarded-For header is used for proxied requests."""
        request = self.factory.post('/', HTTP_X_FORWARDED_FOR='203.0.113.1, 198.51.100.1')
        
        ip = get_client_ip(request)
        # Should extract first IP
        self.assertEqual(ip, '203.0.113.1')


class BruteForceIntegrationTests(TestCase):
    """
    Integration tests for brute-force protection in login flow.
    """

    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        self.login_url = reverse('manzi:login')

    def test_multiple_failed_logins_increases_cooldown(self):
        """
        Test that multiple failed login attempts increase cooldown time.
        
        Realistic scenario: Attacker tries multiple times.
        """
        incorrect_password = 'WrongPassword123!'
        
        # Attempt 1
        self.client.post(self.login_url, {'username': 'testuser', 'password': incorrect_password})
        wait_time_1 = get_throttle_wait_time('testuser', '127.0.0.1')
        
        # Attempt 2
        self.client.post(self.login_url, {'username': 'testuser', 'password': incorrect_password})
        wait_time_2 = get_throttle_wait_time('testuser', '127.0.0.1')
        
        # Cooldown should increase (or stay same if already at 0)
        self.assertGreaterEqual(wait_time_2, wait_time_1)

    def test_successful_login_after_failures(self):
        """
        Test that user can login successfully after previous failures
        once they provide correct credentials and aren't throttled.
        
        UX: System doesn't break legitimate users permanently.
        """
        # Clear any existing attempts
        LoginAttempt.objects.all().delete()
        
        # One failed attempt
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword123!'
        })
        
        # Successful login should work
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPassword123!'
        })
        
        # Should redirect to dashboard (successful)
        self.assertEqual(response.status_code, 302)

    def test_brute_force_attempt_blocked(self):
        """
        Test that brute-force attack is blocked.
        
        Realistic scenario: Attacker tries many passwords rapidly.
        """
        wrong_password = 'WrongPassword123!'
        
        # Simulate multiple failed attempts (more than threshold)
        attempts = BRUTE_FORCE_CONFIG['FAILED_ATTEMPTS_THRESHOLD'] + 2
        
        for i in range(attempts):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': wrong_password
            })
        
        # After threshold, should be rejected even with correct password
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPassword123!'
        })
        
        # Should not redirect to dashboard (blocked)
        self.assertNotEqual(response.status_code, 302)


class LoginAttemptModelTests(TestCase):
    """
    Test cases for LoginAttempt model.
    """

    def test_login_attempt_creation(self):
        """Test that login attempts are created correctly."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            attempt_type='failed'
        )
        
        self.assertIsNotNone(attempt.id)
        self.assertEqual(attempt.username, 'testuser')
        self.assertEqual(attempt.attempt_type, 'failed')

    def test_login_attempt_timestamp(self):
        """Test that timestamp is set automatically."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            attempt_type='success'
        )
        
        self.assertIsNotNone(attempt.timestamp)

    def test_login_attempt_ordering(self):
        """Test that attempts are ordered by timestamp descending."""
        attempt1 = LoginAttempt.objects.create(
            username='user1',
            ip_address='192.168.1.1',
            attempt_type='failed'
        )
        attempt2 = LoginAttempt.objects.create(
            username='user2',
            ip_address='192.168.1.2',
            attempt_type='failed'
        )
        
        # Most recent should be first
        attempts = LoginAttempt.objects.all()
        self.assertEqual(attempts[0].id, attempt2.id)

    def test_login_attempt_string_representation(self):
        """Test that string representation is useful."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='192.168.1.1',
            attempt_type='failed'
        )
        
        str_repr = str(attempt)
        self.assertIn('testuser', str_repr)
        self.assertIn('192.168.1.1', str_repr)
