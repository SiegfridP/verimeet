"""
WSGI config for core project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.1/howto/deployment/wsgi/
"""

import logging
import os
from collections.abc import Mapping

from django.conf import settings
from django.core.wsgi import get_wsgi_application
from django.db import DEFAULT_DB_ALIAS, connections, router

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

application = get_wsgi_application()

# Temporary Render startup diagnostic. Inspect only the connection configuration.
try:
    from accounts.models import Department

    _connection = connections[router.db_for_read(Department)]
    _affinities = getattr(settings, 'DEPARTMENT_DELETION_SESSION_AFFINITY', {})
    _affinity = _affinities.get(_connection.alias) if isinstance(_affinities, Mapping) else None
    _host = str(_connection.settings_dict.get('HOST', '')).lower()
    logging.getLogger('gunicorn.error').info(
        'Department deletion startup guard default_alias=%s affinity_accepted=%s '
        'host_has_pooler=%s host_has_pgbouncer=%s settings_module=%s',
        _connection.alias == DEFAULT_DB_ALIAS,
        _affinity in ('direct', 'session'),
        '-pooler' in _host,
        'pgbouncer' in _host,
        settings.SETTINGS_MODULE,
    )
except Exception:
    logging.getLogger('gunicorn.error').warning('Department deletion startup diagnostic failed.')
