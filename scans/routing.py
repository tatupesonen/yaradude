"""WebSocket routes (mounted by config.asgi)."""

from django.urls import path

from scans.consumers import ScanJobsConsumer

websocket_urlpatterns = [
    path("ws/scans/", ScanJobsConsumer.as_asgi()),
]
