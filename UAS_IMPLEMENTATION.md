# MANZI User Authentication Service (UAS) Implementation

## Overview

This document describes the complete implementation of a Django-based User Authentication Service (UAS) in the `manzi` app. The implementation demonstrates production-style conventions, secure defaults, and a maintainable project structure.

## Project Structure

```
manzi/
├── admin.py                    # Django admin configuration
├── apps.py                     # App configuration with signal imports
├── forms.py                    # Forms for registration, login, password change, profile
├── models.py                   # UserProfile model extending Django's User model
├── signals.py                  # Signals for automatic UserProfile creation
├── urls.py                     # URL routing for the authentication app
├── views.py                    # Views for all authentication flows
├── tests.py                    # Comprehensive test suite
├── templates/manzi/            # HTML templates
│   ├── base.html              # Base template with navigation
│   ├── home.html              # Home page
│   ├── register.html          # User registration page
│   ├── login.html             # User login page
│   ├── dashboard.html         # Protected dashboard (authenticated area)
│   ├── profile.html           # User profile view
│   ├── profile_edit.html      # Profile editing page
│   └── password_change.html   # Password change page
└── migrations/                # Database migrations

```

## Features Implemented

### 1. User Registration
- **Endpoint**: `/register/`
- **Method**: GET/POST
- **Features**:
  - Email validation
  - Duplicate username/email checking
  - Password strength validation (Django built-in validators)
  - Password confirmation matching
  - Automatic UserProfile creation on registration
  - Auto-login after successful registration
  - User-friendly error messages

### 2. User Login
- **Endpoint**: `/login/`
- **Method**: GET/POST
- **Features**:
  - Login by username or email
  - "Remember me" functionality (30-day session)
  - Session-based authentication
  - Secure password verification using Django's hashing
  - Optional redirect to next page after login
  - Input validation and error handling

### 3. User Logout
- **Endpoint**: `/logout/`
- **Method**: GET
- **Features**:
  - Secure session clearing
  - Confirmation message
  - Protected by @login_required decorator
  - Redirects to login page after logout

### 4. Protected Authenticated Area
- **Endpoint**: `/dashboard/`
- **Features**:
  - Login required (@login_required decorator)
  - User welcome message with profile information
  - Quick access to profile, password change, and logout
  - Display of last login and member since dates

### 5. User Profile
- **View Page**: `/profile/`
- **Edit Page**: `/profile/edit/`
- **Features**:
  - View account information (username, email, name, dates)
  - View profile details (bio, date of birth, profile picture)
  - Edit profile with form validation
  - Email uniqueness validation on update
  - Automatic sync between User and UserProfile objects
  - Timestamps for profile creation and updates

### 6. Password Management
- **Endpoint**: `/password-change/`
- **Features**:
  - Requires current password verification
  - New password strength validation
  - New password confirmation
  - Session retention after password change
  - Clear error messages for validation failures

## Security Features

### Built-in Security
1. **CSRF Protection**: All forms include `{% csrf_token %}` template tag
2. **Password Hashing**: Django's PBKDF2 algorithm with SHA256
3. **Session Management**: Django's session framework with secure cookies
4. **Input Validation**: Both form and model-level validation
5. **SQL Injection Prevention**: Django ORM parameterized queries
6. **Authentication Decorators**: @login_required on protected views
7. **Email Validation**: Built-in Django email validators

### Database Security
- One-to-one relationship with Django's User model
- Automatic UserProfile creation via signals
- Proper use of on_delete=CASCADE for foreign keys
- Database migrations for schema management

### Error Handling
- User-friendly error messages
- No stack traces exposed to users
- Validation errors shown inline in forms
- Proper HTTP status codes (302 redirects, 200 OK, 404 Not Found)

## Forms and Validation

### UserRegistrationForm
- Extends Django's UserCreationForm
- Additional fields: email, first_name, last_name
- Validation:
  - Email uniqueness
  - Username length (minimum 3 characters)
  - Username uniqueness
  - Password strength (Django validators)
  - Password confirmation matching

### UserLoginForm
- Custom form for login
- Fields: username (accepts email or username), password, remember_me
- Validation: Required field validation

### CustomPasswordChangeForm
- Extends Django's PasswordChangeForm
- Fields: old_password, new_password1, new_password2
- Includes password strength validators

### UserProfileForm
- Extends Django's ModelForm for UserProfile
- Additional fields: first_name, last_name, email (from User model)
- Fields: bio, date_of_birth, profile_picture
- Validation: Email uniqueness (excluding current user)

## Models

### UserProfile
```python
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, max_length=500)
    profile_picture = models.ImageField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

**Key Features**:
- One-to-one relationship with User
- Automatically created via signals
- Cascading deletion with User
- Timestamps for auditing

## Views Implementation

### Authentication Views
1. `register_view`: Handle user registration with form processing
2. `login_view`: Authenticate user and create session
3. `logout_view`: Clear session and redirect to login

### Profile Views
1. `dashboard_view`: Protected welcome page with user info
2. `profile_view`: Display user profile information
3. `profile_edit_view`: Edit profile with form validation

### Password Management
1. `password_change_view`: Change user password with validation

### Public Views
1. `home_view`: Landing page, redirects to dashboard if authenticated

## URL Configuration

```python
urlpatterns = [
    path('', home_view, name='home'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/', profile_view, name='profile'),
    path('profile/edit/', profile_edit_view, name='profile_edit'),
    path('password-change/', password_change_view, name='password_change'),
]
```

**URLs are available at**:
- `/` - Home page
- `/register/` - Register new account
- `/login/` - Login to account
- `/logout/` - Logout from account
- `/dashboard/` - Protected user dashboard
- `/profile/` - View user profile
- `/profile/edit/` - Edit user profile
- `/password-change/` - Change password
- `/auth/...` - Same URLs with /auth/ prefix

## Templates

### Base Template (base.html)
- Navigation bar with authenticated/unauthenticated showing
- Message display system
- Responsive design with CSS included
- Footer

### Page Templates
- **home.html**: Landing page with feature list
- **register.html**: Registration form
- **login.html**: Login form with remember me
- **dashboard.html**: User dashboard with quick access
- **profile.html**: Profile information display
- **profile_edit.html**: Profile editing form
- **password_change.html**: Password change form

### Design Features
- Mobile-responsive layout
- Clean, modern styling
- User-friendly form display
- Clear error messages
- Success feedback messages
- Card-based layout

## Testing

### Test Coverage
The implementation includes 31 test cases covering:

#### User Registration Tests (6 tests)
- Page loads successfully ✅
- Successful registration ✅
- Duplicate username rejection ✅
- Duplicate email rejection ✅
- Password mismatch rejection ✅
- Authenticated user redirect ✅

#### User Login Tests (5 tests)
- Page loads successfully ✅
- Successful login ✅
- Login with email ✅
- Invalid credentials rejection ✅
- Authenticated user redirect ✅

#### Logout Tests (2 tests)
- Logout requires authentication ✅
- Successful logout with redirect ✅

#### Dashboard Tests (2 tests)
- Requires authentication ✅
- Authenticated user access ✅

#### Profile Tests (5 tests)
- Requires authentication ✅
- View profile ✅
- Edit profile form load ✅
- Profile update with data validation ✅
- Email uniqueness on update ✅

#### Password Change Tests (5 tests)
- Requires authentication ✅
- Page loads for authenticated ✅
- Successful password change ✅
- Wrong old password rejection ✅
- New password mismatch rejection ✅

#### Model Tests (3 tests)
- UserProfile auto-creation ✅
- UserProfile fields present ✅
- String representation ✅

#### Form Validation Tests (3 tests)
- Registration username length ✅
- Login required fields ✅
- Password change old password requirement ✅

### Test Results
```
Ran 31 tests in 61.374s
OK
```

**All tests PASSED! ✅**

### Running Tests

```bash
# Run all tests for the manzi app
python manage.py test manzi

# Run tests with verbose output
python manage.py test manzi -v 2

# Run specific test class
python manage.py test manzi.tests.UserRegistrationTest

# Run specific test method
python manage.py test manzi.tests.UserRegistrationTest.test_successful_registration
```

## Database Setup

### Creating Database and Tables

```bash
# Create migrations for the manzi app
python manage.py makemigrations

# Apply migrations to create tables
python manage.py migrate

# Create a superuser account for admin access
python manage.py createsuperuser
```

### Database Schema

The implementation uses Django's default SQLite database (`db.sqlite3`) with the following tables:
- `auth_user`: Django's built-in User table
- `manzi_userprofile`: Extended user profile table

## Admin Integration

The UserProfile model is registered with Django admin with:
- List display: user, created_at, updated_at
- List filter: creation and update dates
- Search: by username, email, name
- Read-only: timestamps
- Prevention of manual creation (via signals)

**Access at**: `/admin/manzi/userprofile/`

## Best Practices Implemented

1. **Follow Django Conventions**
   - App naming (lowercase)
   - Model naming (CamelCase)
   - View naming (function_view suffix)
   - Template organization (app_name/template_name.html)

2. **Use Django's Built-in Features**
   - User model and authentication
   - Password validation and hashing
   - Forms and form validation
   - Admin interface
   - Signals for automatic profile creation
   - Decorators for access control

3. **Security Defaults**
   - CSRF tokens on all forms
   - Password strength validation
   - Login required decorators
   - Input validation
   - Secure session handling

4. **Code Organization**
   - Separation of concerns (models, views, forms, templates)
   - Meaningful variable and function names
   - Modular code structure
   - Clear documentation

5. **Error Handling**
   - User-friendly error messages
   - Form validation feedback
   - Proper HTTP responses
   - No sensitive information leaked

6. **Responsive Design**
   - Mobile-friendly templates
   - CSS media queries
   - Accessible forms
   - Clear navigation

## Common Tasks

### Create a Test User via Command Line

```bash
python manage.py shell
>>> from django.contrib.auth.models import User
>>> user = User.objects.create_user(
...     username='testuser',
...     email='test@example.com',
...     password='TestPassword123!'
... )
>>> exit()
```

### Reset Database

```bash
# Delete the database file
rm db.sqlite3

# Re-run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### Run Development Server

```bash
python manage.py runserver
```

Access at: `http://127.0.0.1:8000/`

## Implementation Details

### Signal Handlers
Located in `signals.py`:
- `create_user_profile`: Creates UserProfile when User is created
- `save_user_profile`: Ensures UserProfile exists for all Users

### Automatic Profile Creation
When a user registers, the following happens:
1. Form validation passes
2. User object is created
3. Signal handler automatically creates UserProfile
4. User is auto-logged in
5. Redirected to dashboard

### Session Management
- Default session expires when browser closes
- "Remember me" option extends to 30 days
- Secure session cookies

### Email in Login
The login view supports both username and email:
- If input contains '@', it's treated as email
- Email is used to lookup User, then authenticate by username
- Otherwise, authenticate directly with input as username

## Troubleshooting

### Issue: Migrations Not Applied
```bash
python manage.py makemigrations manzi
python manage.py migrate
```

### Issue: UserProfile Not Created
- Check signals.py is properly imported in apps.py
- Restart Django process

### Issue: CSRF Token Missing
- Ensure form includes `{% csrf_token %}`
- Check CSRF middleware is enabled in settings

### Issue: Login Not Working
- Verify user exists and password is correct
- Check session middleware is enabled
- Ensure DATABASE settings are correct

## Future Enhancements

Potential improvements for production:
1. Email verification on registration
2. Password reset via email
3. Two-factor authentication
4. Social authentication (OAuth)
5. Account deactivation
6. Activity logging
7. API authentication (Token/JWT)
8. Rate limiting on login attempts
9. Profile image optimization
10. User search and recommendations

## Submission Checklist

- [x] App named 'manzi' (student name lowercase)
- [x] Models with UserProfile and relationships
- [x] Forms for registration, login, password management
- [x] Views for all authentication flows
- [x] Templates for all pages
- [x] URL configuration
- [x] Admin integration
- [x] Access control with decorators
- [x] Input validation and error handling
- [x] Test coverage for main flows
- [x] Django best practices followed
- [x] CSRF protection implemented
- [x] No breaking changes to existing functionality
- [x] Clear documentation

## References

- Django Documentation: https://docs.djangoproject.com/
- Django Authentication: https://docs.djangoproject.com/en/6.0/topics/auth/
- Django Forms: https://docs.djangoproject.com/en/6.0/topics/forms/
- Django Testing: https://docs.djangoproject.com/en/6.0/topics/testing/