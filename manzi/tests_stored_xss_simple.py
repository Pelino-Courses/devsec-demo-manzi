"""
Test suite for stored XSS vulnerability prevention in user profiles.

This test suite verifies that malicious user input in profile bios
cannot execute as JavaScript or break out of its intended context.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import UserProfile


class ProfileStoredXSSTests(TestCase):
    """Test stored XSS prevention in user profiles."""
    
    def setUp(self):
        """Create test users."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.profile = UserProfile.objects.get(user=self.user)
        self.client = Client()
    
    def test_script_tag_xss(self):
        """Test that <script> tags in bio are escaped, not executed."""
        payload = "<script>alert('XSS')</script>"
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # Script should be escaped
        self.assertNotIn('<script>alert', content)
        self.assertIn('&lt;script&gt;', content)
    
    def test_img_onerror_xss(self):
        """Test that img onerror handlers are escaped."""
        payload = '<img src=x onerror="alert(\'XSS\')">'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # onerror should not be present as a live attribute
        self.assertNotIn('onerror=', content)
        self.assertIn('&lt;img', content)
    
    def test_svg_onload_xss(self):
        """Test that SVG onload handlers are escaped."""
        payload = '<svg onload="alert(\'XSS\')">'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # onload should not be present
        self.assertNotIn('onload=', content)
        self.assertIn('&lt;svg', content)
    
    def test_onclick_attribute_xss(self):
        """Test that onclick attributes are escaped."""
        payload = '<div onclick="alert(\'clicked\')">'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # onclick should not be present
        self.assertNotIn('onclick=', content)
        self.assertIn('&lt;div', content)
    
    def test_javascript_protocol_xss(self):
        """Test that javascript: protocol is blocked."""
        payload = '<a href="javascript:alert(\'XSS\')">Click</a>'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # javascript: should not be in unescaped form
        self.assertNotIn('href="javascript:', content)
        self.assertIn('&lt;a', content)
    
    def test_iframe_injection(self):
        """Test that iframe injection is prevented."""
        payload = '<iframe src="https://evil.com"></iframe>'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # iframe should be escaped
        self.assertNotIn('<iframe', content)
        self.assertIn('&lt;iframe', content)
    
    def test_form_injection(self):
        """Test that form injection is prevented."""
        payload = '<form action="https://evil.com"><input type="password"></form>'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # form tags should be escaped
        self.assertNotIn('<form action', content)
        self.assertIn('&lt;form', content)
    
    def test_style_tag_xss(self):
        """Test that style tag injection is prevented."""
        payload = '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # style tags should be escaped
        self.assertNotIn('<style', content)
        self.assertIn('&lt;style', content)
    
    def test_legit_text_with_angle_brackets(self):
        """Test that legitimate text with angle brackets is preserved."""
        text = "I like C++ and prefer var < const"
        self.profile.bio = text
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # Text should be present (and safe)
        self.assertIn('C++', content)
        self.assertIn('&lt;', content)  # < should be escaped
    
    def test_unicode_content_preserved(self):
        """Test that Unicode content is preserved and rendered correctly."""
        text = "Hello 世界 🌍 مرحبا Привет"
        self.profile.bio = text
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        
        content = response.content.decode('utf-8')
        # Unicode should be present
        self.assertIn('世界', content)
        self.assertIn('🌍', content)
        self.assertIn('مرحبا', content)
    
    def test_payload_stored_safely(self):
        """Test that XSS payload is stored but rendered safely."""
        payload = '<img src=x onerror="alert(\'stored_xss\')">'
        self.profile.bio = payload
        self.profile.save()
        
        # Verify stored in DB
        stored = UserProfile.objects.get(id=self.profile.id)
        self.assertEqual(stored.bio, payload)
        
        # But when rendered, it's safe
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/')
        content = response.content.decode('utf-8')
        
        # Should not execute
        self.assertNotIn('onerror=', content)


class EditFormXSSTests(TestCase):
    """Test XSS protection in the profile edit form."""
    
    def setUp(self):
        """Create test user."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.profile = UserProfile.objects.get(user=self.user)
        self.client = Client()
    
    def test_edit_form_displays_xss_safely(self):
        """Test that XSS payload in bio is displayed safely in edit form."""
        payload = '<script>alert("XSS")</script>'
        self.profile.bio = payload
        self.profile.save()
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/profile/edit/')
        
        content = response.content.decode('utf-8')
        # Form should display the bio content safely
        # Either escaped in HTML or in a text field
        # Should not have unescaped JS
        self.assertNotIn('<script>alert', content)
    
    def test_bio_preserved_in_form(self):
        """Test that bio content is preserved when submitted in form."""
        bio_content = "My interesting bio with <!-- HTML comment -->"
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post('/profile/edit/', {
            'bio': bio_content,
        })
        
        # Verify bio was stored
        updated = UserProfile.objects.get(id=self.profile.id)
        self.assertEqual(updated.bio, bio_content)
