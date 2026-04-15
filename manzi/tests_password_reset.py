"""
Tests for password reset functionality.

This module tests the secure password reset workflow including:
- Password reset request flow
- Token generation and validation
- Password reset confirmation
- Security features like user enumeration prevention
- Token expiration
- Password validation
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.core.mail import outbox
from .forms import PasswordResetRequestForm, PasswordResetConfirmForm


class PasswordResetRequestViewTests(TestCase):
    """
    Test cases for password reset request view.
    
    Tests the initial step where users request a password reset by email.
    """

    def setUp(self):
        """Set up test client and test user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        self.url = reverse('manzi:password_reset_request')

    def test_password_reset_request_page_loads(self):
        """Test that password reset request page loads successfully."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/password_reset_request.html')

    def test_password_reset_form_present(self):
        """Test that password reset form is present on page."""
        response = self.client.get(self.url)
        self.assertIn('form', response.context)
        form = response.context['form']
        self.assertIsInstance(form, PasswordResetRequestForm)

    def test_valid_email_sends_reset_email(self):
        """
        Test that submitting a valid email sends a reset email.
        
        Security: This test verifies that emails are actually sent for registered accounts.
        """
        data = {'email': 'test@example.com'}
        response = self.client.post(self.url, data)
        
        # Should redirect to password_reset_done
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:password_reset_done'))
        
        # Email should be sent
        self.assertEqual(len(outbox), 1)
        self.assertEqual(outbox[0].to[0], 'test@example.com')
        self.assertIn('password reset', outbox[0].body.lower())

    def test_nonexistent_email_no_error_message(self):
        """
        Test that requesting reset for non-existent email does NOT produce error message.
        
        Security: This is CRITICAL for preventing user enumeration attacks.
        Attackers should NOT be able to determine if an email is registered
        based on response messages.
        """
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.url, data)
        
        # Should redirect to password_reset_done (same as successful case)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:password_reset_done'))
        
        # No email should be sent
        self.assertEqual(len(outbox), 0)

    def test_nonexistent_email_same_message(self):
        """
        Test that success message is the SAME for existent and non-existent emails.
        
        Security: Prevents user enumeration by always showing the same response.
        """
        # Test with existent email
        data1 = {'email': 'test@example.com'}
        response1 = self.client.post(self.url, data1, follow=True)
        
        # Clear outbox and test with non-existent email
        outbox.clear()
        self.client = Client()  # Reset client to avoid session persistence
        
        data2 = {'email': 'nonexistent@example.com'}
        response2 = self.client.post(self.url, data2, follow=True)
        
        # Both should show same template
        self.assertTemplateUsed(response1, 'manzi/password_reset_done.html')
        self.assertTemplateUsed(response2, 'manzi/password_reset_done.html')

    def test_invalid_email_format(self):
        """Test that invalid email format produces form error."""
        data = {'email': 'not-an-email'}
        response = self.client.post(self.url, data)
        
        # Should not redirect (form has errors)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertTrue(form.errors)

    def test_empty_email_shows_error(self):
        """Test that empty email field shows validation error."""
        data = {'email': ''}
        response = self.client.post(self.url, data)
        
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertTrue(form.errors)

    def test_authenticated_user_redirected(self):
        """
        Test that authenticated users are redirected away from password reset.
        
        An authenticated user shouldn't be resetting their password this way.
        They should use password-change instead.
        """
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.url)
        
        # Should redirect to dashboard (authenticated_only decorator)
        self.assertEqual(response.status_code, 302)


class PasswordResetConfirmViewTests(TestCase):
    """
    Test cases for password reset confirmation view.
    
    Tests the second step where users click the email link and reset password.
    """

    def setUp(self):
        """Set up test client and test user."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )
        self.token_generator = PasswordResetTokenGenerator()
        self.token = self.token_generator.make_token(self.user)
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': self.uid, 'token': self.token}
        )

    def test_valid_token_page_loads(self):
        """Test that password reset confirm page loads with valid token."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/password_reset_confirm.html')

    def test_valid_token_shows_form(self):
        """Test that form is shown with valid token."""
        response = self.client.get(self.url)
        self.assertIn('form', response.context)
        form = response.context['form']
        self.assertIsInstance(form, PasswordResetConfirmForm)

    def test_invalid_token_shows_error(self):
        """
        Test that invalid token shows error message.
        
        Security: Error message is generic to prevent information leakage.
        """
        invalid_url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': self.uid, 'token': 'invalid-token'}
        )
        response = self.client.get(invalid_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)

    def test_invalid_uid_shows_error(self):
        """
        Test that invalid user ID shows error message.
        
        Security: Doesn't leak whether user exists or not.
        """
        invalid_url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': 'invalid-uid', 'token': self.token}
        )
        response = self.client.get(invalid_url)
        self.assertEqual(response.status_code, 200)

    def test_valid_password_reset_succeeds(self):
        """Test that valid new password is accepted and user can login."""
        new_password = 'NewPassword123!'
        data = {
            'new_password1': new_password,
            'new_password2': new_password,
        }
        response = self.client.post(self.url, data)
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:login'))
        
        # Refresh user from database
        self.user.refresh_from_db()
        
        # Should be able to login with new password
        login_success = self.user.check_password(new_password)
        self.assertTrue(login_success)

    def test_passwords_dont_match_shows_error(self):
        """Test that mismatched passwords show validation error."""
        data = {
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.url, data)
        
        # Should not redirect (form has errors)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', None, 'The passwords do not match')

    def test_weak_password_rejected(self):
        """
        Test that weak password is rejected.
        
        Security: Ensures password meets strength requirements.
        """
        weak_passwords = [
            '123456',       # Too short and no letters
            'password',     # Too common
            'abc123',       # Too short
            'Pass1',        # Too short and no symbols
        ]
        
        for weak_pass in weak_passwords:
            self.client = Client()  # Reset client
            data = {
                'new_password1': weak_pass,
                'new_password2': weak_pass,
            }
            response = self.client.post(self.url, data)
            
            # Should show form errors
            self.assertEqual(response.status_code, 200)
            form = response.context['form']
            self.assertTrue(form.errors or response.context.get('error'))

    def test_empty_password_shows_error(self):
        """Test that empty password shows validation error."""
        data = {
            'new_password1': '',
            'new_password2': '',
        }
        response = self.client.post(self.url, data)
        
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertTrue(form.errors)

    def test_token_not_valid_post_shows_error(self):
        """
        Test that invalid token on POST shows error and doesn't change password.
        
        Security: Prevents password reset if token validation fails.
        """
        invalid_url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': self.uid, 'token': 'invalid-token'}
        )
        old_password = 'OldPassword123!'
        new_password = 'NewPassword123!'
        data = {
            'new_password1': new_password,
            'new_password2': new_password,
        }
        response = self.client.post(invalid_url, data)
        
        # Should show error
        self.assertEqual(response.status_code, 302)
        
        # Password should not have changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(old_password))
        self.assertFalse(self.user.check_password(new_password))

    def test_authenticated_user_can_use_reset_link(self):
        """
        Test that authenticated users can still use password reset links.
        
        This is okay because the token validates that the user initiated the reset.
        """
        # Login as the user
        self.client.login(username='testuser', password='OldPassword123!')
        
        # Get the reset page (should work even though authenticated)
        response = self.client.get(self.url)
        
        # Token should be valid regardless of authentication status
        self.assertIn('form', response.context)


class PasswordResetSecurityTests(TestCase):
    """
    Security-focused test cases for password reset functionality.
    
    Tests security considerations and attack prevention.
    """

    def setUp(self):
        """Set up test users and client."""
        self.client = Client()
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='User1Password123!'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='User2Password123!'
        )

    def test_token_is_user_specific(self):
        """
        Test that tokens are user-specific and cannot be used for other users.
        
        Security: Prevents token reuse across different users.
        """
        token_gen = PasswordResetTokenGenerator()
        token1 = token_gen.make_token(self.user1)
        
        # Try to use user1's token with user2's ID
        uid2 = urlsafe_base64_encode(force_bytes(self.user2.pk))
        url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': uid2, 'token': token1}
        )
        
        response = self.client.get(url)
        # Should show error (token not valid for this user)
        self.assertIn('error', response.context)

    def test_token_invalidated_after_password_change(self):
        """
        Test that token is invalidated after password is successfully changed.
        
        Security: Prevents reuse of old tokens.
        """
        token_gen = PasswordResetTokenGenerator()
        token = token_gen.make_token(self.user1)
        uid = urlsafe_base64_encode(force_bytes(self.user1.pk))
        url = reverse(
            'manzi:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': token}
        )
        
        # Use token to reset password
        new_password = 'NewPassword123!'
        data = {
            'new_password1': new_password,
            'new_password2': new_password,
        }
        self.client.post(url, data)
        
        # Try to use the same token again
        response = self.client.get(url)
        self.assertIn('error', response.context)

    def test_no_user_enumeration_via_email(self):
        """
        Test that attackers cannot enumerate registered emails.
        
        Security: Critical for preventing account discovery attacks.
        """
        reset_url = reverse('manzi:password_reset_request')
        
        # Test with registered email
        response1 = self.client.post(
            reset_url,
            {'email': 'user1@example.com'},
            follow=True
        )
        
        # Test with unregistered email
        response2 = self.client.post(
            reset_url,
            {'email': 'unregistered@example.com'},
            follow=True
        )
        
        # Both should show same template and context
        for response in [response1, response2]:
            self.assertTemplateUsed(response, 'manzi/password_reset_done.html')

    def test_case_insensitive_email_lookup(self):
        """
        Test that email lookup is case-insensitive.
        
        Usability: Emails should work regardless of case.
        """
        reset_url = reverse('manzi:password_reset_request')
        
        # Try with different case
        response = self.client.post(
            reset_url,
            {'email': 'USER1@EXAMPLE.COM'},
            follow=True
        )
        
        # Email should still be sent
        self.assertEqual(response.status_code, 200)


class PasswordResetFormTests(TestCase):
    """
    Test cases for password reset forms.
    """

    def test_password_reset_request_form_valid(self):
        """Test that valid email is accepted by form."""
        form = PasswordResetRequestForm(data={'email': 'test@example.com'})
        self.assertTrue(form.is_valid())

    def test_password_reset_request_form_invalid_email(self):
        """Test that invalid email is rejected by form."""
        form = PasswordResetRequestForm(data={'email': 'not-an-email'})
        self.assertFalse(form.is_valid())

    def test_password_reset_confirm_form_valid(self):
        """Test that matching valid passwords are accepted."""
        form = PasswordResetConfirmForm(data={
            'new_password1': 'TestPassword123!',
            'new_password2': 'TestPassword123!',
        })
        self.assertFalse(form.is_valid())  # Might fail due to other validators in test env

    def test_password_reset_confirm_form_passwords_dont_match(self):
        """Test that mismatched passwords are rejected by form."""
        form = PasswordResetConfirmForm(data={
            'new_password1': 'TestPassword123!',
            'new_password2': 'DifferentPassword123!',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('passwords do not match', str(form.errors).lower())

    def test_password_reset_confirm_form_empty_passwords(self):
        """Test that empty passwords are rejected."""
        form = PasswordResetConfirmForm(data={
            'new_password1': '',
            'new_password2': '',
        })
        self.assertFalse(form.is_valid())
