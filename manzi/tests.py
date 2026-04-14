"""
Comprehensive tests for the MANZI Authentication Service.

This module tests the core authentication lifecycle and ensures
all views, forms, and models work correctly and securely.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from .models import UserProfile
from .forms import UserRegistrationForm, UserLoginForm, CustomPasswordChangeForm, UserProfileForm


class UserRegistrationTest(TestCase):
    """Test cases for user registration functionality."""

    def setUp(self):
        self.client = Client()
        self.register_url = reverse('manzi:register')

    def test_register_page_loads(self):
        """Test that registration page loads successfully."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/register.html')

    def test_successful_registration(self):
        """Test successful user registration."""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'TestPassword123!',
            'password2': 'TestPassword123!',
        }
        response = self.client.post(self.register_url, data)
        
        # Check if user was created
        self.assertTrue(User.objects.filter(username='testuser').exists())
        
        # Check if there's a UserProfile created
        user = User.objects.get(username='testuser')
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        
        # Check if user is redirected to dashboard after registration
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))

    def test_registration_duplicate_username(self):
        """Test registration with duplicate username."""
        User.objects.create_user(username='testuser', email='test1@example.com', password='pass123')
        
        data = {
            'username': 'testuser',
            'email': 'test2@example.com',
            'password1': 'TestPassword123!',
            'password2': 'TestPassword123!',
        }
        response = self.client.post(self.register_url, data)
        
        # Should not redirect (form has errors) and only 1 user should exist
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(username='testuser').count(), 1)

    def test_registration_duplicate_email(self):
        """Test registration with duplicate email."""
        User.objects.create_user(username='testuser1', email='test@example.com', password='pass123')
        
        data = {
            'username': 'testuser2',
            'email': 'test@example.com',
            'password1': 'TestPassword123!',
            'password2': 'TestPassword123!',
        }
        response = self.client.post(self.register_url, data)
        
        # Should not redirect (form has errors) and only 1 user with this email
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(email='test@example.com').count(), 1)

    def test_registration_password_mismatch(self):
        """Test registration with mismatched passwords."""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'TestPassword123!',
            'password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.register_url, data)
        
        # User should not be created
        self.assertFalse(User.objects.filter(username='testuser').exists())

    def test_authenticated_user_redirect_from_register(self):
        """Test that authenticated users are redirected from register page."""
        user = User.objects.create_user(username='testuser', email='test@example.com', password='pass123')
        self.client.login(username='testuser', password='pass123')
        
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))


class UserLoginTest(TestCase):
    """Test cases for user login functionality."""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse('manzi:login')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_login_page_loads(self):
        """Test that login page loads successfully."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/login.html')

    def test_successful_login(self):
        """Test successful user login."""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!',
        }
        response = self.client.post(self.login_url, data)
        
        # Check if redirected to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))

    def test_login_with_email(self):
        """Test login using email instead of username."""
        data = {
            'username': 'test@example.com',
            'password': 'TestPassword123!',
        }
        response = self.client.post(self.login_url, data)
        
        # Check if redirected to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword123!',
        }
        response = self.client.post(self.login_url, data)
        
        # Should not redirect
        self.assertEqual(response.status_code, 200)

    def test_authenticated_user_redirect_from_login(self):
        """Test that authenticated users are redirected from login page."""
        self.client.login(username='testuser', password='TestPassword123!')
        
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))


class UserLogoutTest(TestCase):
    """Test cases for user logout functionality."""

    def setUp(self):
        self.client = Client()
        self.logout_url = reverse('manzi:logout')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_logout_requires_authentication(self):
        """Test that logout redirects unauthenticated users to login."""
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)

    def test_successful_logout(self):
        """Test successful user logout."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.logout_url)
        
        # Check if redirected to login
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:login'))


class DashboardViewTest(TestCase):
    """Test cases for dashboard (protected area)."""

    def setUp(self):
        self.client = Client()
        self.dashboard_url = reverse('manzi:dashboard')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_dashboard_requires_authentication(self):
        """Test that dashboard requires authentication."""
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302)

    def test_authenticated_user_can_access_dashboard(self):
        """Test that authenticated users can access dashboard."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.dashboard_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/dashboard.html')
        self.assertContains(response, self.user.username)


class ProfileViewTest(TestCase):
    """Test cases for profile viewing and editing."""

    def setUp(self):
        self.client = Client()
        self.profile_url = reverse('manzi:profile')
        self.profile_edit_url = reverse('manzi:profile_edit')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            password='TestPassword123!'
        )
        self.profile = UserProfile.objects.get(user=self.user)

    def test_profile_requires_authentication(self):
        """Test that profile view requires authentication."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)

    def test_authenticated_user_can_view_profile(self):
        """Test that authenticated users can view their profile."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/profile.html')
        self.assertContains(response, self.user.username)

    def test_profile_edit_requires_authentication(self):
        """Test that profile edit requires authentication."""
        response = self.client.get(self.profile_edit_url)
        self.assertEqual(response.status_code, 302)

    def test_profile_edit_loads_for_authenticated_user(self):
        """Test that profile edit form loads for authenticated users."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get(self.profile_edit_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/profile_edit.html')

    def test_profile_update(self):
        """Test that user can update their profile."""
        self.client.login(username='testuser', password='TestPassword123!')
        
        data = {
            'first_name': 'UpdatedTest',
            'last_name': 'UpdatedUser',
            'email': 'test@example.com',
            'bio': 'This is my bio',
        }
        response = self.client.post(self.profile_edit_url, data)
        
        # Refresh user from database
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'UpdatedTest')
        self.assertEqual(self.user.last_name, 'UpdatedUser')
        
        # Refresh profile from database
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.bio, 'This is my bio')


class PasswordChangeTest(TestCase):
    """Test cases for password change functionality."""

    def setUp(self):
        self.client = Client()
        self.password_change_url = reverse('manzi:password_change')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='OldPassword123!'
        )

    def test_password_change_requires_authentication(self):
        """Test that password change requires authentication."""
        response = self.client.get(self.password_change_url)
        self.assertEqual(response.status_code, 302)

    def test_password_change_page_loads(self):
        """Test that password change page loads for authenticated users."""
        self.client.login(username='testuser', password='OldPassword123!')
        response = self.client.get(self.password_change_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'manzi/password_change.html')

    def test_successful_password_change(self):
        """Test successful password change."""
        self.client.login(username='testuser', password='OldPassword123!')
        
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.password_change_url, data)
        
        # Check if redirected to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('manzi:dashboard'))

    def test_password_change_wrong_old_password(self):
        """Test password change with wrong old password."""
        self.client.login(username='testuser', password='OldPassword123!')
        
        data = {
            'old_password': 'WrongPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        }
        response = self.client.post(self.password_change_url, data)
        
        # Should not redirect (form has errors)
        self.assertEqual(response.status_code, 200)

    def test_password_change_mismatch(self):
        """Test password change with mismatched new passwords."""
        self.client.login(username='testuser', password='OldPassword123!')
        
        data = {
            'old_password': 'OldPassword123!',
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword123!',
        }
        response = self.client.post(self.password_change_url, data)
        
        # Should not redirect (form has errors)
        self.assertEqual(response.status_code, 200)


class UserProfileModelTest(TestCase):
    """Test cases for UserProfile model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )

    def test_user_profile_auto_created(self):
        """Test that UserProfile is automatically created when User is created."""
        self.assertTrue(UserProfile.objects.filter(user=self.user).exists())

    def test_user_profile_fields(self):
        """Test that UserProfile has expected fields."""
        profile = UserProfile.objects.get(user=self.user)
        
        self.assertIsNotNone(profile.created_at)
        self.assertIsNotNone(profile.updated_at)
        self.assertEqual(profile.bio, '')
        self.assertIsNone(profile.date_of_birth)

    def test_user_profile_string_representation(self):
        """Test UserProfile string representation."""
        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(str(profile), f'Profile of {self.user.username}')


class FormValidationTest(TestCase):
    """Test cases for form validation."""

    def test_registration_form_short_username(self):
        """Test registration form with username that's too short."""
        form = UserRegistrationForm(data={
            'username': 'ab',
            'email': 'test@example.com',
            'password1': 'TestPassword123!',
            'password2': 'TestPassword123!',
        })
        self.assertFalse(form.is_valid())

    def test_login_form_required_fields(self):
        """Test login form with missing fields."""
        form = UserLoginForm(data={
            'username': '',
            'password': '',
        })
        self.assertFalse(form.is_valid())

    def test_password_change_form_requires_old_password(self):
        """Test that password change form requires old password."""
        user = User.objects.create_user(
            username='testuser',
            password='OldPassword123!'
        )
        form = CustomPasswordChangeForm(user, data={
            'old_password': '',
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!',
        })
        self.assertFalse(form.is_valid())
