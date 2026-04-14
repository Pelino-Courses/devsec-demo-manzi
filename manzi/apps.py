"""
Django app configuration for the MANZI authentication service.
"""

from django.apps import AppConfig


class ManziConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'manzi'
    verbose_name = 'MANZI Authentication Service'

    def ready(self):
        """Import signals when the app is ready."""
        import manzi.signals
