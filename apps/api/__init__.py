"""ASGI entry: ``uvicorn apps.api:app --factory`` is not used; prefer ``aisec serve``."""

from aisec.cloud.app import create_app

app = create_app
