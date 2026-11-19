"""Shared view helpers."""

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.http import content_disposition_header

from rules.services.exporter import ExportFile

PAGE_SIZE = 100


class PermissionMixin(PermissionRequiredMixin):
    """
    Permission check that answers 403 for a signed-in user who lacks the
    permission (anonymous users never get here: LoginRequiredMiddleware
    redirects them to the sign-in page first).
    """

    raise_exception = True

    def dispatch(self, request, *args, **kwargs):
        # Check the permission before anything looks up an object, so a user
        # without it gets 403 whether or not the id exists.
        if not self.has_permission():
            return self.handle_no_permission()
        self.load(**kwargs)
        return super().dispatch(request, *args, **kwargs)

    def load(self, **kwargs) -> None:
        """Hook to load the view's object after the permission check."""


def paginate(request, queryset, per_page: int = PAGE_SIZE):
    """The requested page of `queryset`; out-of-range or invalid numbers give the nearest page."""
    paginator = Paginator(queryset, per_page)
    return paginator.get_page(request.GET.get("page"))


def file_response(export: ExportFile) -> HttpResponse:
    return HttpResponse(
        export.content,
        content_type=export.content_type,
        headers={"Content-Disposition": content_disposition_header(True, export.filename)},
    )
