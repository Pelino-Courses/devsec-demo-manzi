"""
URL configuration for the MANZI authentication app.

This module defines all URL patterns for user authentication flows and profile management.
Includes staff/admin endpoints for user management with proper IDOR prevention.
"""

from django.urls import path
from . import views

app_name = 'manzi'

urlpatterns = [
    # Public authentication endpoints
    path('', views.home_view, name='home'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Password reset endpoints
    path('password-reset/', views.password_reset_request_view, name='password_reset_request'),
    path('password-reset/done/', views.password_reset_done_view, name='password_reset_done'),
    path('password-reset/<str:uidb64>/<str:token>/', views.password_reset_confirm_view, name='password_reset_confirm'),

    # Protected authenticated endpoints
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.profile_edit_view, name='profile_edit'),
    path('profile/upload-picture/', views.profile_picture_upload_view, name='profile_picture_upload'),  # CSRF-protected AJAX endpoint
    path('password-change/', views.password_change_view, name='password_change'),
    
    # Staff/Admin user management endpoints
    # IDOR Prevention: These endpoints accept user IDs but verify authorization
    path('admin/users/', views.user_list_view, name='user_list'),
    path('admin/users/<int:user_id>/', views.user_profile_view, name='user_profile_view'),
    path('admin/users/<int:user_id>/edit/', views.user_profile_edit_admin, name='user_profile_edit_admin'),
]