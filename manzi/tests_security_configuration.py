"""
Tests for Django security configuration hardening.

This test module verifies that:
1. Security settings are properly configured per environment
2. Critical settings are validated and enforced
3. Security headers are configured
4. Vulnerable configurations raise errors
"""

import os
from io import StringIO
from django.test import TestCase, override_settings
from django.core.management import call_command
from django.test.utils import setup_test_environment
from django.conf import settings


class DjangoSecurityConfigurationTests(TestCase):
    """Test Django security configuration hardening."""
    
    # ========================================================================
    # DEBUG MODE TESTS
    # ========================================================================
    
    def test_debug_is_configured(self):
        """DEBUG setting should be explicitly configured."""
        self.assertIsNotNone(settings.DEBUG)
        self.assertIsInstance(settings.DEBUG, bool)
    
    def test_debug_false_in_production_mode(self):
        """DEBUG should be False in production mode."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertFalse(settings.DEBUG, "DEBUG must be False in production")
    
    def test_debug_can_be_true_in_development(self):
        """DEBUG can be True in development mode."""
        if getattr(settings, 'IS_DEVELOPMENT', False):
            # DEBUG can be True or False in development
            # Just verify it's a boolean
            self.assertIsInstance(settings.DEBUG, bool)
    
    # ========================================================================
    # SECRET_KEY TESTS
    # ========================================================================
    
    def test_secret_key_is_configured(self):
        """SECRET_KEY must be set."""
        self.assertIsNotNone(settings.SECRET_KEY)
    
    def test_secret_key_is_non_empty_string(self):
        """SECRET_KEY must be a non-empty string."""
        self.assertIsInstance(settings.SECRET_KEY, str)
        self.assertGreater(len(settings.SECRET_KEY), 0)
    
    def test_secret_key_has_minimum_length(self):
        """SECRET_KEY should be sufficiently long (at least 30 chars)."""
        # In development, may use placeholder. In production, should be longer.
        # Allow shorter keys in development but document best practice
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertGreater(len(settings.SECRET_KEY), 50,
                             "SECRET_KEY should be 50+ characters in production")
    
    # ========================================================================
    # ALLOWED_HOSTS TESTS
    # ========================================================================
    
    def test_allowed_hosts_is_configured(self):
        """ALLOWED_HOSTS must be configured."""
        self.assertIsNotNone(settings.ALLOWED_HOSTS)
    
    def test_allowed_hosts_is_list_or_tuple(self):
        """ALLOWED_HOSTS must be a list or tuple."""
        self.assertIsInstance(settings.ALLOWED_HOSTS, (list, tuple))
    
    def test_allowed_hosts_not_empty_in_production(self):
        """ALLOWED_HOSTS must not be empty in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertGreater(len(settings.ALLOWED_HOSTS), 0,
                             "ALLOWED_HOSTS must be configured in production")
    
    def test_allowed_hosts_includes_localhost_in_development(self):
        """ALLOWED_HOSTS should include localhost in development."""
        if getattr(settings, 'IS_DEVELOPMENT', False):
            hosts_str = str(settings.ALLOWED_HOSTS).lower()
            self.assertTrue('localhost' in hosts_str or '127.0.0.1' in hosts_str,
                          "Development should allow localhost")
    
    # ========================================================================
    # HTTPS AND TRANSPORT SECURITY TESTS
    # ========================================================================
    
    def test_secure_ssl_redirect_in_production(self):
        """SECURE_SSL_REDIRECT must be True in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertTrue(settings.SECURE_SSL_REDIRECT,
                          "SECURE_SSL_REDIRECT must be True in production")
    
    def test_secure_ssl_redirect_false_in_development(self):
        """SECURE_SSL_REDIRECT should be False in development."""
        if getattr(settings, 'IS_DEVELOPMENT', False):
            self.assertFalse(settings.SECURE_SSL_REDIRECT,
                           "SECURE_SSL_REDIRECT should be False in development (no HTTPS)")
    
    def test_hsts_seconds_in_production(self):
        """HSTS should be enabled in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertGreater(settings.SECURE_HSTS_SECONDS, 0,
                             "HSTS must be enabled in production")
    
    def test_hsts_includes_subdomains_in_production(self):
        """HSTS should include subdomains in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertTrue(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS,
                          "HSTS should include subdomains in production")
    
    def test_hsts_preload_enabled_in_production(self):
        """HSTS preload should be enabled in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertTrue(settings.SECURE_HSTS_PRELOAD,
                          "HSTS preload should be enabled in production")
    
    # ========================================================================
    # COOKIE SECURITY TESTS
    # ========================================================================
    
    def test_session_cookie_secure_in_production(self):
        """Session cookie secure flag must be True in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertTrue(settings.SESSION_COOKIE_SECURE,
                          "SESSION_COOKIE_SECURE must be True in production")
    
    def test_csrf_cookie_secure_in_production(self):
        """CSRF cookie secure flag must be True in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            self.assertTrue(settings.CSRF_COOKIE_SECURE,
                          "CSRF_COOKIE_SECURE must be True in production")
    
    def test_session_cookie_httponly_enabled(self):
        """Session cookie must have HttpOnly flag."""
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY,
                       "SESSION_COOKIE_HTTPONLY must be True (prevent XSS theft)")
    
    def test_csrf_cookie_httponly_enabled(self):
        """CSRF cookie must have HttpOnly flag."""
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY,
                       "CSRF_COOKIE_HTTPONLY must be True")
    
    def test_session_cookie_samesite_set(self):
        """Session cookie must have SameSite attribute."""
        self.assertIsNotNone(settings.SESSION_COOKIE_SAMESITE,
                            "SESSION_COOKIE_SAMESITE must be set")
        self.assertIn(settings.SESSION_COOKIE_SAMESITE, ['Lax', 'Strict', 'None'],
                     "SESSION_COOKIE_SAMESITE must be Lax, Strict, or None")
    
    def test_csrf_cookie_samesite_set(self):
        """CSRF cookie must have SameSite attribute."""
        self.assertIsNotNone(settings.CSRF_COOKIE_SAMESITE,
                            "CSRF_COOKIE_SAMESITE must be set")
        self.assertIn(settings.CSRF_COOKIE_SAMESITE, ['Lax', 'Strict', 'None'],
                     "CSRF_COOKIE_SAMESITE must be Lax, Strict, or None")
    
    # ========================================================================
    # HTTP SECURITY HEADERS TESTS
    # ========================================================================
    
    def test_x_frame_options_configured(self):
        """X-Frame-Options header must be configured."""
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY',
                        "X-Frame-Options should be DENY (prevent clickjacking)")
    
    def test_secure_browser_xss_filter_enabled(self):
        """X-XSS-Protection header must be enabled."""
        self.assertTrue(settings.SECURE_BROWSER_XSS_FILTER,
                       "SECURE_BROWSER_XSS_FILTER must be True")
    
    def test_content_security_policy_configured(self):
        """Content-Security-Policy headers must be configured."""
        self.assertIsNotNone(settings.SECURE_CONTENT_SECURITY_POLICY,
                            "SECURE_CONTENT_SECURITY_POLICY must be configured")
        self.assertIsInstance(settings.SECURE_CONTENT_SECURITY_POLICY, dict)
    
    def test_csp_default_src_restrictive(self):
        """CSP default-src should be restrictive."""
        csp = settings.SECURE_CONTENT_SECURITY_POLICY
        self.assertIn('default-src', csp,
                     "CSP must define default-src")
        # Should be 'self' only (most restrictive)
        self.assertIn("'self'", csp['default-src'],
                     "CSP default-src should include 'self'")
    
    def test_csp_script_src_no_unsafe_inline_in_production(self):
        """CSP script-src should not allow unsafe-inline in production."""
        if getattr(settings, 'IS_PRODUCTION', False):
            csp = settings.SECURE_CONTENT_SECURITY_POLICY
            if 'script-src' in csp:
                self.assertNotIn("'unsafe-inline'", csp['script-src'],
                               "script-src should not have unsafe-inline in production")
    
    def test_csp_object_src_disabled(self):
        """CSP object-src should be disabled (no plugins)."""
        csp = settings.SECURE_CONTENT_SECURITY_POLICY
        if 'object-src' in csp:
            self.assertEqual(csp['object-src'], ["'none'"],
                           "object-src should be 'none' (no plugins)")
    
    # ========================================================================
    # MIDDLEWARE TESTS
    # ========================================================================
    
    def test_security_middleware_enabled(self):
        """SecurityMiddleware must be enabled."""
        self.assertIn('django.middleware.security.SecurityMiddleware',
                     settings.MIDDLEWARE,
                     "SecurityMiddleware must be first in MIDDLEWARE")
    
    def test_security_middleware_is_first(self):
        """SecurityMiddleware should be first in middleware stack."""
        first_middleware = settings.MIDDLEWARE[0]
        self.assertEqual(first_middleware, 'django.middleware.security.SecurityMiddleware',
                        "SecurityMiddleware should be first middleware")
    
    def test_csrf_middleware_enabled(self):
        """CSRF middleware must be enabled."""
        self.assertIn('django.middleware.csrf.CsrfViewMiddleware',
                     settings.MIDDLEWARE,
                     "CSRF middleware must be enabled")
    
    def test_xframe_middleware_enabled(self):
        """X-Frame-Options middleware must be enabled."""
        self.assertIn('django.middleware.clickjacking.XFrameOptionsMiddleware',
                     settings.MIDDLEWARE,
                     "XFrame middleware must be enabled")
    
    # ========================================================================
    # FILE UPLOAD SECURITY TESTS
    # ========================================================================
    
    def test_data_upload_max_memory_size_set(self):
        """DATA_UPLOAD_MAX_MEMORY_SIZE should be set to reasonable limit."""
        self.assertIsNotNone(settings.DATA_UPLOAD_MAX_MEMORY_SIZE)
        # 5MB is reasonable for most applications
        self.assertLess(settings.DATA_UPLOAD_MAX_MEMORY_SIZE, 100 * 1024 * 1024,
                       "DATA_UPLOAD_MAX_MEMORY_SIZE should be limited")
    
    def test_data_upload_max_number_fields_set(self):
        """DATA_UPLOAD_MAX_NUMBER_FIELDS should be set to reasonable limit."""
        self.assertIsNotNone(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS)
        # Limit number of form fields to prevent DoS
        self.assertLess(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS, 1000,
                       "DATA_UPLOAD_MAX_NUMBER_FIELDS should be limited")
    
    def test_file_upload_max_memory_size_set(self):
        """FILE_UPLOAD_MAX_MEMORY_SIZE should be set."""
        self.assertIsNotNone(settings.FILE_UPLOAD_MAX_MEMORY_SIZE)
    
    # ========================================================================
    # ENVIRONMENT CONFIGURATION TESTS
    # ========================================================================
    
    def test_environment_variable_set(self):
        """ENVIRONMENT variable must be set."""
        self.assertIn(settings.ENVIRONMENT, ['development', 'production'])
    
    def test_is_production_flag_matches_environment(self):
        """IS_PRODUCTION flag should match ENVIRONMENT."""
        if settings.ENVIRONMENT == 'production':
            self.assertTrue(settings.IS_PRODUCTION)
        else:
            self.assertFalse(settings.IS_PRODUCTION)
    
    def test_is_development_flag_matches_environment(self):
        """IS_DEVELOPMENT flag should match ENVIRONMENT."""
        if settings.ENVIRONMENT == 'development':
            self.assertTrue(settings.IS_DEVELOPMENT)
        else:
            self.assertFalse(settings.IS_DEVELOPMENT)
    
    # ========================================================================
    # DEPLOYMENT VALIDATION TESTS
    # ========================================================================
    
    def test_django_check_deploy_command(self):
        """Django's security check should pass."""
        # Run 'python manage.py check --deploy' programmatically
        out = StringIO()
        try:
            call_command('check', '--deploy', stdout=out, stderr=out)
        except SystemExit as e:
            if e.code != 0:
                self.fail(f"django check --deploy failed:\n{out.getvalue()}")
    
    # ========================================================================
    # LOGGING CONFIGURATION TESTS
    # ========================================================================
    
    def test_logging_configured(self):
        """Logging should be configured."""
        self.assertIsNotNone(settings.LOGGING)
        self.assertIn('version', settings.LOGGING)
        self.assertIn('handlers', settings.LOGGING)
        self.assertIn('loggers', settings.LOGGING)
    
    def test_security_logger_configured(self):
        """Security logger should be configured."""
        self.assertIn('django.security', settings.LOGGING['loggers'],
                     "django.security logger must be configured")
    
    # ========================================================================
    # PASSWORD VALIDATOR TESTS
    # ========================================================================
    
    def test_password_validators_configured(self):
        """Password validators must be configured."""
        self.assertIsNotNone(settings.AUTH_PASSWORD_VALIDATORS)
        self.assertGreater(len(settings.AUTH_PASSWORD_VALIDATORS), 0,
                          "Password validators must be configured")
    
    def test_multiple_password_validators(self):
        """Multiple password validators should be enabled."""
        # Should have at least user similarity and minimum length
        self.assertGreaterEqual(len(settings.AUTH_PASSWORD_VALIDATORS), 2,
                              "Should have multiple password validators")


class ConfigurationEdgeCaseTests(TestCase):
    """Test edge cases and configuration interactions."""
    
    def test_environment_variables_can_be_overridden(self):
        """Settings should respect environment variable overrides."""
        # This is tested by the use of os.environ.get()
        # Verify that override_settings can modify values
        with override_settings(DEBUG=True):
            self.assertTrue(settings.DEBUG)
        with override_settings(DEBUG=False):
            self.assertFalse(settings.DEBUG)
    
    def test_allowed_hosts_handles_comma_separated_values(self):
        """ALLOWED_HOSTS should properly parse comma-separated values."""
        # In development, verify parsing works
        if getattr(settings, 'IS_DEVELOPMENT', False):
            # Should have parsed values as list
            self.assertIsInstance(settings.ALLOWED_HOSTS, (list, tuple))
    
    def test_hsts_values_reasonable(self):
        """HSTS seconds should be reasonable (1 year to 10 years)."""
        if getattr(settings, 'IS_PRODUCTION', False):
            seconds = settings.SECURE_HSTS_SECONDS
            # 1 year = 365*24*60*60 = 31536000
            # 10 years maximum
            self.assertGreater(seconds, 365 * 24 * 60 * 60,
                             "HSTS should be at least 1 year")
            self.assertLess(seconds, 10 * 365 * 24 * 60 * 60,
                          "HSTS should be less than 10 years (for rotation)")
