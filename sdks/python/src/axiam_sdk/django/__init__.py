"""Django integration package marker (D-10, CONTRACT.md §10).

Imported ONLY as ``axiam_sdk.django`` / ``axiam_sdk.django.middleware``
(never from the top-level ``axiam_sdk/__init__.py``), so pure-REST/gRPC/AMQP
consumers of ``axiam-sdk`` are never forced to install ``django``.
"""

from __future__ import annotations
