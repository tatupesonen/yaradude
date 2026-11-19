from django.contrib.auth.decorators import login_not_required  # ty: ignore[missing-module-member]  # Django 5.1 API absent from django-types 0.24
from django.db import DatabaseError, connection
from django.http import HttpRequest, HttpResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe


@login_not_required
@never_cache
@require_safe
def healthz(request: HttpRequest) -> HttpResponse:
    """Liveness and database check for the container health check."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except DatabaseError:
        return HttpResponse("database unavailable\n", status=503, content_type="text/plain")
    return HttpResponse("ok\n", content_type="text/plain")
