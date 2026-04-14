"""
Tests for authorization and access control in the MANZI application.

This test suite verifies that:
1. Role-based access control is properly enforced
2. Authorized users can access protected views
3. Unauthorized users are denied access appropriately
4. Decorators work correctly
5. Permissions are properly assigned
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group, Permission
from django.urls import reverse
from manzi.models import UserProfile
from manzi.authorization import (
    has_role,
    has_instructor_role,
    has_staff_role,
    has_admin_role,
    assign_role_to_user,
    remove_role_from_user,
    get_user_roles,
    Roles,
    setup_authorization_groups,
)


class AuthorizationSetupTest(TestCase):
    """Test authorization group setup and initialization."""

    def setUp(self):
        """Initialize authorization groups."""
        setup_authorization_groups()

    def test_groups_created(self):
        """Test that all authorized groups are created."""
        expected_groups = ['instructor', 'staff']
        for group_name in expected_groups:
            group = Group.objects.get(name=group_name)
            self.assertIsNotNone(group)

    def test_permissions_assigned_to_groups(self):
        """Test that permissions are assigned to groups."""
        instructor_group = Group.objects.get(name=Roles.INSTRUCTOR)
        self.assertGreater(instructor_group.permissions.count(), 0)

        staff_group = Group.objects.get(name=Roles.STAFF)
        self.assertGreater(staff_group.permissions.count(), 0)


class RoleCheckFunctionsTest(TestCase):
    """Test role-checking utility functions."""

    def setUp(self):
        """Create test users with different roles."""
        setup_authorization_groups()
        
        # Anonymous user (no user object)
        self.anonymous_user = None
        
        # Regular authenticated user
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@test.com',
            password='testpass123'
        )
        
        # Instructor user
        self.instructor_user = User.objects.create_user(
            username='instructor',
            email='instructor@test.com',
            password='testpass123'
        )
        instructor_group = Group.objects.get(name=Roles.INSTRUCTOR)
        self.instructor_user.groups.add(instructor_group)
        
        # Staff user
        self.staff_user = User.objects.create_user(
            username='staff',
            email='staff@test.com',
            password='testpass123'
        )
        staff_group = Group.objects.get(name=Roles.STAFF)
        self.staff_user.groups.add(staff_group)
        
        # Admin (superuser)
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@test.com',
            password='testpass123'
        )

    def test_has_role_anonymous(self):
        """Test anonymous role check."""
        self.assertTrue(has_role(None, Roles.ANONYMOUS))
        self.assertFalse(has_role(self.regular_user, Roles.ANONYMOUS))

    def test_has_role_authenticated(self):
        """Test authenticated role check."""
        self.assertFalse(has_role(None, Roles.AUTHENTICATED))
        self.assertTrue(has_role(self.regular_user, Roles.AUTHENTICATED))

    def test_has_instructor_role(self):
        """Test instructor role check."""
        self.assertFalse(has_instructor_role(self.regular_user))
        self.assertTrue(has_instructor_role(self.instructor_user))
        self.assertTrue(has_instructor_role(self.admin_user))

    def test_has_staff_role(self):
        """Test staff role check."""
        self.assertFalse(has_staff_role(self.regular_user))
        self.assertTrue(has_staff_role(self.staff_user))
        self.assertTrue(has_staff_role(self.admin_user))

    def test_has_admin_role(self):
        """Test admin role check."""
        self.assertFalse(has_admin_role(self.regular_user))
        self.assertFalse(has_admin_role(self.instructor_user))
        self.assertTrue(has_admin_role(self.admin_user))

    def test_get_user_roles(self):
        """Test getting all user roles."""
        roles = get_user_roles(self.regular_user)
        self.assertIn(Roles.AUTHENTICATED, roles)
        
        instructor_roles = get_user_roles(self.instructor_user)
        self.assertIn(Roles.AUTHENTICATED, instructor_roles)
        self.assertIn(Roles.INSTRUCTOR, instructor_roles)
        
        admin_roles = get_user_roles(self.admin_user)
        self.assertIn(Roles.ADMIN, admin_roles)


class RoleAssignmentTest(TestCase):
    """Test role assignment and removal."""

    def setUp(self):
        """Create test users."""
        setup_authorization_groups()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@test.com',
            password='testpass123'
        )

    def test_assign_instructor_role(self):
        """Test assigning instructor role."""
        result = assign_role_to_user(self.user, Roles.INSTRUCTOR)
        self.assertTrue(result)
        self.assertTrue(has_instructor_role(self.user))

    def test_assign_staff_role(self):
        """Test assigning staff role."""
        result = assign_role_to_user(self.user, Roles.STAFF)
        self.assertTrue(result)
        self.assertTrue(has_staff_role(self.user))

    def test_assign_admin_role(self):
        """Test assigning admin role."""
        result = assign_role_to_user(self.user, Roles.ADMIN)
        self.assertTrue(result)
        self.assertTrue(has_admin_role(self.user))

    def test_remove_instructor_role(self):
        """Test removing instructor role."""
        assign_role_to_user(self.user, Roles.INSTRUCTOR)
        self.assertTrue(has_instructor_role(self.user))
        
        result = remove_role_from_user(self.user, Roles.INSTRUCTOR)
        self.assertTrue(result)
        self.user.refresh_from_db()
        self.assertFalse(has_instructor_role(self.user))

    def test_remove_admin_role(self):
        """Test removing admin role."""
        assign_role_to_user(self.user, Roles.ADMIN)
        self.assertTrue(has_admin_role(self.user))
        
        result = remove_role_from_user(self.user, Roles.ADMIN)
        self.assertTrue(result)
        self.user.refresh_from_db()
        self.assertFalse(has_admin_role(self.user))


class ViewAccessControlTest(TestCase):
    """Test access control for views using decorators."""

    def setUp(self):
        """Set up test client and users."""
        setup_authorization_groups()
        self.client = Client()
        
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@test.com',
            password='testpass123'
        )
        UserProfile.objects.create(user=self.regular_user)
        
        self.instructor_user = User.objects.create_user(
            username='instructor',
            email='instructor@test.com',
            password='testpass123'
        )
        UserProfile.objects.create(user=self.instructor_user)
        instructor_group = Group.objects.get(name=Roles.INSTRUCTOR)
        self.instructor_user.groups.add(instructor_group)

    def test_register_view_anonymous_access(self):
        """Test anonymous users can access register view."""
        response = self.client.get(reverse('manzi:register'))
        self.assertEqual(response.status_code, 200)

    def test_register_view_authenticated_redirect(self):
        """Test authenticated users are redirected from register."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:register'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)

    def test_login_view_anonymous_access(self):
        """Test anonymous users can access login view."""
        response = self.client.get(reverse('manzi:login'))
        self.assertEqual(response.status_code, 200)

    def test_login_view_authenticated_redirect(self):
        """Test authenticated users are redirected from login."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:login'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('dashboard', response.url)

    def test_dashboard_view_anonymous_redirect(self):
        """Test anonymous users are redirected from dashboard."""
        response = self.client.get(reverse('manzi:dashboard'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_dashboard_view_authenticated_access(self):
        """Test authenticated users can access dashboard."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_profile_view_anonymous_redirect(self):
        """Test anonymous users are redirected from profile."""
        response = self.client.get(reverse('manzi:profile'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_profile_view_authenticated_access(self):
        """Test authenticated users can access their profile."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:profile'))
        self.assertEqual(response.status_code, 200)

    def test_profile_edit_view_authenticated_access(self):
        """Test authenticated users can access profile edit."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:profile_edit'))
        self.assertEqual(response.status_code, 200)

    def test_password_change_view_authenticated_access(self):
        """Test authenticated users can access password change."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:password_change'))
        self.assertEqual(response.status_code, 200)

    def test_logout_view_authenticated_access(self):
        """Test authenticated users can logout."""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('manzi:logout'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_logout_view_anonymous_redirect(self):
        """Test anonymous users are redirected from logout."""
        response = self.client.get(reverse('manzi:logout'), follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)


class LoginAccessTest(TestCase):
    """Test login flow and account creation."""

    def setUp(self):
        """Set up test client."""
        setup_authorization_groups()
        self.client = Client()

    def test_successful_registration(self):
        """Test user can successfully register."""
        response = self.client.post(reverse('manzi:register'), {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
        }, follow=True)
        
        # Should redirect to dashboard after successful registration
        self.assertIn('dashboard', response.redirect_chain[0][0])

    def test_successful_login(self):
        """Test user can successfully login."""
        User.objects.create_user(
            username='testuser',
            email='test@test.com',
            password='testpass123'
        )
        UserProfile.objects.create(user=User.objects.get(username='testuser'))
        
        response = self.client.post(reverse('manzi:login'), {
            'username': 'testuser',
            'password': 'testpass123',
        }, follow=True)
        
        self.assertIn('dashboard', response.redirect_chain[0][0])

    def test_login_with_email(self):
        """Test user can login using email instead of username."""
        user = User.objects.create_user(
            username='testuser',
            email='test@test.com',
            password='testpass123'
        )
        UserProfile.objects.create(user=user)
        
        response = self.client.post(reverse('manzi:login'), {
            'username': 'test@test.com',
            'password': 'testpass123',
        }, follow=True)
        
        self.assertIn('dashboard', response.redirect_chain[0][0])
