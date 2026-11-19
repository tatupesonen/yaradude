"""Views of the web UI. Every view declares the permission it needs."""

from rules.views.dashboard import DashboardView
from rules.views.imports import ImportRunView, ImportScanView, ImportUploadView, ImportView
from rules.views.rules import (
    RuleCreateView,
    RuleDeleteView,
    RuleDetailView,
    RuleDownloadView,
    RuleEditView,
    RuleExportView,
    RuleListView,
    RuleRestoreView,
    RuleVersionView,
)
from rules.views.rulesets import (
    RulesetDeleteView,
    RulesetDetailView,
    RulesetDownloadView,
    RulesetListView,
    RulesetOriginalView,
)
from rules.views.scan import ScanView

__all__ = [
    "DashboardView",
    "ImportRunView",
    "ImportScanView",
    "ImportUploadView",
    "ImportView",
    "RuleCreateView",
    "RuleDeleteView",
    "RuleDetailView",
    "RuleDownloadView",
    "RuleEditView",
    "RuleExportView",
    "RuleListView",
    "RuleRestoreView",
    "RuleVersionView",
    "RulesetDeleteView",
    "RulesetDetailView",
    "RulesetDownloadView",
    "RulesetListView",
    "RulesetOriginalView",
    "ScanView",
]
