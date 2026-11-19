from django.urls import path

from rules import views

app_name = "rules"

urlpatterns = [
    path("", views.DashboardView.as_view(), name="dashboard"),
    path("rules/", views.RuleListView.as_view(), name="rule_list"),
    path("rules/new/", views.RuleCreateView.as_view(), name="rule_create"),
    path("rules/export/", views.RuleExportView.as_view(), name="rule_export"),
    path("rules/<int:pk>/", views.RuleDetailView.as_view(), name="rule_detail"),
    path("rules/<int:pk>/edit/", views.RuleEditView.as_view(), name="rule_edit"),
    path("rules/<int:pk>/delete/", views.RuleDeleteView.as_view(), name="rule_delete"),
    path("rules/<int:pk>/download/", views.RuleDownloadView.as_view(), name="rule_download"),
    path(
        "rules/<int:pk>/versions/<int:number>/",
        views.RuleVersionView.as_view(),
        name="rule_version",
    ),
    path(
        "rules/<int:pk>/versions/<int:number>/restore/",
        views.RuleRestoreView.as_view(),
        name="rule_restore",
    ),
    path("rulesets/", views.RulesetListView.as_view(), name="ruleset_list"),
    path("rulesets/<int:pk>/", views.RulesetDetailView.as_view(), name="ruleset_detail"),
    path(
        "rulesets/<int:pk>/download/",
        views.RulesetDownloadView.as_view(),
        name="ruleset_download",
    ),
    path(
        "rulesets/<int:pk>/original/",
        views.RulesetOriginalView.as_view(),
        name="ruleset_original",
    ),
    path("rulesets/<int:pk>/delete/", views.RulesetDeleteView.as_view(), name="ruleset_delete"),
    path("import/", views.ImportView.as_view(), name="import"),
    path("import/scan/", views.ImportScanView.as_view(), name="import_scan"),
    path("import/upload/", views.ImportUploadView.as_view(), name="import_upload"),
    path("import/runs/<int:pk>/", views.ImportRunView.as_view(), name="import_run"),
    path("scan/", views.ScanView.as_view(), name="scan"),
]
