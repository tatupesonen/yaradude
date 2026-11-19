import os
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Create the first superuser from DJANGO_SUPERUSER_USERNAME, "
        "DJANGO_SUPERUSER_PASSWORD and DJANGO_SUPERUSER_EMAIL if that user does "
        "not exist. Never changes an existing account; does nothing when "
        "DJANGO_SUPERUSER_USERNAME is unset. The password must pass the "
        "configured password validators."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "").strip()
        if not username:
            self.stdout.write("DJANGO_SUPERUSER_USERNAME is not set; no superuser created.")
            return
        User = get_user_model()
        if User.objects.filter(username=username).exists():
            self.stdout.write(f'User "{username}" already exists; left unchanged.')
            return
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")
        if not password:
            raise CommandError("DJANGO_SUPERUSER_PASSWORD is required to create the superuser.")
        email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "").strip()
        # A weak password is an error, not a warning: this account has every
        # permission, the command runs unattended at container start where a
        # warning goes unread, and refusing changes nothing that exists (the
        # operator sets a stronger password in .env and restarts).
        try:
            validate_password(password, User(username=username, email=email))
        except ValidationError as error:
            raise CommandError(
                "DJANGO_SUPERUSER_PASSWORD is too weak: " + " ".join(error.messages)
            ) from None
        User.objects.create_superuser(username=username, email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f'Superuser "{username}" created.'))
