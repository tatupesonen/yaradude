"""
ASGI entry point (`config.asgi.application`), served by uvicorn.

HTTP goes to Django as before; WebSocket connections go through Channels to
the live scan socket (`/ws/scans/`, PLAN.md 12.7). There is no channel
layer. The consumer authenticates from the session cookie and checks the
user's permission and the Origin header itself.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Set up Django (and the app registry) before importing anything that uses models.
django_application = get_asgi_application()

from channels.auth import AuthMiddlewareStack  # noqa: E402
from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402

from scans.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_application,
        "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
    }
)
