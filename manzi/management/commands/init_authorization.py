"""
Management command to initialize authorization groups and permissions.

Usage:
    python manage.py init_authorization
"""

from django.core.management.base import BaseCommand
from manzi.authorization import setup_authorization_groups


class Command(BaseCommand):
    help = 'Initialize authorization groups and permissions for RBAC'

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Initializing authorization groups and permissions...')
        )
        
        setup_authorization_groups()
        
        self.stdout.write(
            self.style.SUCCESS(
                'Authorization setup completed successfully!'
            )
        )
