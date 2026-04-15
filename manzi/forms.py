"""
Forms for user authentication and profile management.

This module provides forms for registration, login, password management,
and profile updates using Django's built-in forms and custom validation.
"""

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from django.core.exceptions import ValidationError
from .models import UserProfile


class UserRegistrationForm(UserCreationForm):
    """
    Extended registration form with email and profile information.
    
    Uses Django's built-in UserCreationForm with additional fields and custom validation.
    """
    email = forms.EmailField(
        required=True,
        help_text='A valid email address for account verification'
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        help_text='Optional'
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        help_text='Optional'
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')

    def clean_email(self):
        """Validate that email is unique."""
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exists():
            raise ValidationError('This email address is already registered.')
        return email

    def clean_username(self):
        """Validate username format."""
        username = self.cleaned_data.get('username')
        if username and User.objects.filter(username=username).exists():
            raise ValidationError('This username is already taken.')
        if username and len(username) < 3:
            raise ValidationError('Username must be at least 3 characters long.')
        return username

    def save(self, commit=True):
        """Save the user and create an associated UserProfile."""
        user = super().save(commit=False)
        user.email = self.cleaned_data.get('email')
        if commit:
            user.save()
            # Create an associated UserProfile
            UserProfile.objects.get_or_create(user=user)
        return user


class UserLoginForm(forms.Form):
    """
    Simple login form for username and password authentication.
    """
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username or Email'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        help_text='Remember me for 30 days'
    )

    def clean(self):
        """Basic validation - specific user/password validation happens in views."""
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if not username:
            self.add_error('username', 'Username is required.')
        if not password:
            self.add_error('password', 'Password is required.')

        return cleaned_data


class CustomPasswordChangeForm(PasswordChangeForm):
    """
    Extended password change form with better styling and validation.
    """
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='Current Password'
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='New Password'
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='Confirm New Password'
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)


class UserProfileForm(forms.ModelForm):
    """
    Form for updating user profile information.
    """
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label='First Name'
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label='Last Name'
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        label='Email Address'
    )

    class Meta:
        model = UserProfile
        fields = ('bio', 'date_of_birth', 'profile_picture')
        widgets = {
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Tell us about yourself'
            }),
            'date_of_birth': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'profile_picture': forms.FileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.user:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            self.fields['email'].initial = self.instance.user.email

    def clean_email(self):
        """Validate that email is unique (excluding current user)."""
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(pk=self.instance.user.pk).exists():
            raise ValidationError('This email address is already in use.')
        return email

    def save(self, commit=True):
        """Save profile and update associated User object."""
        profile = super().save(commit=False)
        user = profile.user
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')
        user.email = self.cleaned_data.get('email')
        
        if commit:
            user.save()
            profile.save()
        return profile


# ============================================================================
# Password Reset Forms
# ============================================================================

class PasswordResetRequestForm(forms.Form):
    """
    Form for requesting a password reset.
    
    Security Notes:
    - Only requires email field
    - Does not provide information about whether email exists or not
    - Prevents user enumeration through messaging
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        }),
        help_text='We will send you a link to reset your password'
    )

    def clean_email(self):
        """
        Validate email format.
        
        Note: We intentionally do NOT check if the email exists in the database.
        This is to prevent user enumeration attacks where attackers could determine
        if an email address is registered by observing different error messages.
        
        The actual existence check happens in the view, which always shows
        the same success message regardless.
        """
        email = self.cleaned_data.get('email')
        return email


class PasswordResetConfirmForm(forms.Form):
    """
    Form for confirming password reset and setting new password.
    
    Security Notes:
    - Uses Django's built-in password validators
    - Requires password confirmation
    - Validates password strength
    """
    new_password1 = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password'
        }),
        help_text='Password must be at least 8 characters long, include uppercase, lowercase, numbers, and special characters'
    )
    new_password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password'
        })
    )

    def clean(self):
        """Validate that passwords match."""
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2:
            if password1 != password2:
                raise ValidationError('The passwords do not match. Please try again.')
        
        return cleaned_data

    def clean_new_password1(self):
        """Validate password using Django's validators."""
        from django.contrib.auth.password_validation import validate_password
        password = self.cleaned_data.get('new_password1')
        
        if password:
            try:
                validate_password(password)
            except ValidationError as e:
                raise ValidationError(str(e))
        
        return password