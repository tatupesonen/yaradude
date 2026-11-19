from django.db.models import Count, F, Q
from django.views.generic import TemplateView

from rules.models import ImportRun, Rule, Ruleset, Tag
from rules.views.base import PermissionMixin

ACTIVE = Q(removed_at__isnull=True)


class DashboardView(PermissionMixin, TemplateView):
    permission_required = "rules.view_rule"
    template_name = "rules/dashboard.html"

    def get_context_data(self, **kwargs):
        counts = Rule.objects.aggregate(
            rules=Count("pk", filter=ACTIVE),
            failing=Count("pk", filter=ACTIVE & ~Q(compile_error="")),
            warnings=Count("pk", filter=ACTIVE & Q(compile_error="") & ~Q(compile_warnings=[])),
            modified=Count(
                "pk", filter=ACTIVE & ~Q(imported_sha256="") & ~Q(sha256=F("imported_sha256"))
            ),
            removed=Count("pk", filter=~ACTIVE),
        )
        return super().get_context_data(
            counts=counts,
            ruleset_count=Ruleset.objects.count(),
            tag_count=Tag.objects.count(),
            recent_runs=ImportRun.objects.select_related("user")[:6],
            recent_rules=(
                Rule.objects.active()
                .select_related("ruleset")
                .defer("source", "meta", "ruleset__original_content")
                .order_by("-updated_at", "-pk")[:10]
            ),
            **kwargs,
        )
