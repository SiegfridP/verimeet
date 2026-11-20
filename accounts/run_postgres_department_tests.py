"""Guarded local runner. Default/--check-config is static and never connects."""
import argparse
import ipaddress
import os
import sys
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest.mock import patch

SETTINGS = 'core.postgres_test_settings'
TARGET = 'verimeet_concurrency_test'
SQLITE_TEST_NAME = 'file:memorydb_deletion_test?mode=memory&cache=shared'
EXPECTED = {'ENGINE':'django.db.backends.postgresql', 'HOST':'127.0.0.1',
            'PORT':'5432', 'NAME':TARGET, 'USER':'verimeet_test_user1'}
ALLOWED = ('accounts.test_department_deletion', 'accounts.test_batch14',
           'meetings.test_attendance_integrity', 'meetings.test_roster_integrity',
           'meetings.test_visual_evidence', 'meetings.tests.Batch09StructuredAuditTests',
           'meetings.tests.Batch09MeetingAdminAuditTests',
           'meetings.tests.Batch09AuditCorrectionAdminTests')


def validate_configuration(require_password=False):
    from django.conf import Settings, UserSettingsHolder, settings
    # override_settings() masks SETTINGS_MODULE with None. Verify the loaded
    # base module, then read the effective configuration through LazySettings.
    effective_module = settings.SETTINGS_MODULE
    base = settings._wrapped
    while isinstance(base, UserSettingsHolder):
        base = base.default_settings
    if (not isinstance(base, Settings) or base.SETTINGS_MODULE != SETTINGS
            or effective_module not in (None, SETTINGS)
            or set(settings.DATABASES) != {'default', 'deletion_test'}):
        raise RuntimeError('Unexpected test settings or database aliases.')
    config = settings.DATABASES['default']
    if any(config.get(key) != value for key, value in EXPECTED.items()):
        raise RuntimeError('Refusing database target outside the disposable local environment.')
    if (config.get('ATOMIC_REQUESTS') is not False or config.get('AUTOCOMMIT') is not True
            or config.get('TEST', {}).get('NAME') != TARGET
            or config.get('OPTIONS', {}).get('pool')):
        raise RuntimeError('Unexpected test transaction configuration.')
    if config.get('OPTIONS') != {'connect_timeout':5, 'sslmode':'disable',
            'options':'-c lock_timeout=5000 -c statement_timeout=30000'}:
        raise RuntimeError('Unexpected PostgreSQL connection options.')
    if settings.DEPARTMENT_DELETION_SESSION_AFFINITY != {'default':'direct'}:
        raise RuntimeError('Unexpected session affinity.')
    if not is_approved_sqlite(settings.DATABASES['deletion_test']):
        raise RuntimeError('Secondary alias must be in-memory SQLite.')
    if require_password and not config.get('PASSWORD'):
        raise RuntimeError('Set VERIMEET_PG_TEST_PASSWORD before executing tests.')


def is_approved_sqlite(config):
    return (config.get('ENGINE') == 'django.db.backends.sqlite3'
            and config.get('NAME') == SQLITE_TEST_NAME
            and config.get('TEST', {}).get('NAME') == SQLITE_TEST_NAME
            and not any(config.get(field) for field in ('HOST', 'PORT', 'USER'))
            and config.get('OPTIONS', {}) == {})


_EXECUTION_APPROVED = False

_GUARDS_INSTALLED = False
_RAW_CONNECT = None
from contextvars import ContextVar
_DRIVER_ALLOWED = ContextVar('local_pg_driver_allowed', default=False)


_PREFLIGHT_CATEGORIES = frozenset({
    'Identity query failure', 'Identity result shape/type mismatch',
    'Database/user/address/port mismatch', 'Backend PID mismatch',
    'Identity-probe rollback failure',
})


def safe_exception_details(exc):
    import re
    name = type(exc).__name__
    details = ' exception=' + (name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) else 'Exception')
    code = getattr(exc, 'sqlstate', None)
    if isinstance(code, str) and re.fullmatch(r'[A-Z0-9]{5}', code):
        details += ' SQLSTATE=' + code
    return details


class PreflightDiagnosticError(RuntimeError):
    """Only fixed categories/field labels and sanitized exception metadata."""
    def __init__(self, category, exc=None, field=None):
        if category not in _PREFLIGHT_CATEGORIES:
            raise ValueError('Unknown preflight diagnostic category.')
        message = category
        if field in {'database', 'user', 'address', 'port'}:
            message += ' field=' + field
        if exc is not None:
            message += safe_exception_details(exc)
        super().__init__(message)


def safe_connection_error(exc):
    return RuntimeError('Local PostgreSQL connection failed.' + safe_exception_details(exc))


def validate_wrapper(wrapper):
    validate_configuration(require_password=True)
    if not _EXECUTION_APPROVED:
        raise RuntimeError('Database access requires explicit authorization from the dedicated runner.')
    config = wrapper.settings_dict
    if wrapper.alias == 'default':
        if (any(config.get(key) != value for key, value in EXPECTED.items())
                or config.get('OPTIONS') != {'connect_timeout':5, 'sslmode':'disable',
                    'options':'-c lock_timeout=5000 -c statement_timeout=30000'}
                or config.get('ATOMIC_REQUESTS') is not False
                or config.get('AUTOCOMMIT') is not True):
            raise RuntimeError('Django connection rejected: unapproved local database configuration.')
    elif wrapper.alias != 'deletion_test' or not is_approved_sqlite(config):
        raise RuntimeError('Django connection rejected: unapproved alias or database.')


def approved_server_address(value):
    """Match one IPv4 host, including inet::text's explicit /32 suffix."""
    if type(value) is ipaddress.IPv4Address:
        return value == ipaddress.IPv4Address('127.0.0.1')
    if type(value) is not str:
        return False
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        return False
    return (type(interface) is ipaddress.IPv4Interface
            and interface.network.prefixlen == 32
            and interface.ip == ipaddress.IPv4Address('127.0.0.1'))


def verify_identity(raw):
    try:
        with raw.cursor() as cursor:
            cursor.execute('SELECT current_database(), current_user, inet_server_addr()::text, inet_server_port(), pg_backend_pid()')
            row = cursor.fetchone()
    except Exception as exc:
        raise PreflightDiagnosticError('Identity query failure', exc) from None
    if (not isinstance(row, tuple) or len(row) != 5
            or any(type(value) is not str for value in row[:2])
            or type(row[2]) not in (str, ipaddress.IPv4Address, ipaddress.IPv6Address)
            or any(type(value) is not int for value in row[3:])):
        raise PreflightDiagnosticError('Identity result shape/type mismatch')
    for field, value, expected in zip(('database', 'user', 'address', 'port'), row[:4],
                                     (TARGET, EXPECTED['USER'], '127.0.0.1', 5432)):
        matches = approved_server_address(value) if field == 'address' else value == expected
        if not matches:
            raise PreflightDiagnosticError('Database/user/address/port mismatch', field=field)
    try:
        backend_pid = raw.info.backend_pid
    except Exception as exc:
        raise PreflightDiagnosticError('Backend PID mismatch', exc) from None
    if type(backend_pid) is not int or row[4] != backend_pid:
        raise PreflightDiagnosticError('Backend PID mismatch')


def install_guards():
    """Process-local guard installed by settings, including manage.py use.

    This protects reviewed tests against accidental routing/configuration changes;
    it is not a sandbox for hostile Python code able to undo monkey patches.
    """
    global _GUARDS_INSTALLED, _RAW_CONNECT
    if _GUARDS_INSTALLED:
        return
    _GUARDS_INSTALLED = True
    import socket
    import psycopg
    from django.db.backends.base.base import BaseDatabaseWrapper
    from django.db.backends.postgresql.base import DatabaseWrapper
    original_ensure = BaseDatabaseWrapper.ensure_connection
    original_connect = BaseDatabaseWrapper.connect
    original_new = DatabaseWrapper.get_new_connection
    _RAW_CONNECT = psycopg.Connection.connect

    def ensure(wrapper):
        validate_wrapper(wrapper)
        return original_ensure(wrapper)

    def connect(wrapper):
        validate_wrapper(wrapper)
        return original_connect(wrapper)

    def driver_connect(*args, **kwargs):
        if not _EXECUTION_APPROVED or not _DRIVER_ALLOWED.get() or args:
            raise RuntimeError('Direct psycopg connections are prohibited; use approved Django connections.')
        required = {'host':'127.0.0.1', 'port':'5432', 'dbname':TARGET, 'user':EXPECTED['USER'],
                    'connect_timeout':5, 'sslmode':'disable',
                    'options':'-c lock_timeout=5000 -c statement_timeout=30000'}
        allowed = set(required) | {'password', 'client_encoding', 'cursor_factory', 'context', 'prepare_threshold'}
        if set(kwargs) - allowed or any(kwargs.get(key) != value for key, value in required.items()):
            raise RuntimeError('Driver connection rejected: unapproved target or parameters.')
        try:
            raw = _RAW_CONNECT(**kwargs)
        except psycopg.Error as exc:
            raise safe_connection_error(exc) from None
        try:
            verify_identity(raw)
            try:
                raw.rollback()  # End only the read-only identity probe's transaction.
            except Exception as exc:
                raise PreflightDiagnosticError('Identity-probe rollback failure', exc) from None
        except PreflightDiagnosticError as diagnostic:
            try:
                raw.close()
            except Exception as exc:
                # Preserve the original diagnostic without exposing cleanup text.
                raise RuntimeError(str(diagnostic) + '; connection close failed.' +
                                   safe_exception_details(exc)) from None
            raise diagnostic from None
        return raw

    def new(wrapper, params):
        validate_wrapper(wrapper)
        token = _DRIVER_ALLOWED.set(True)
        try:
            return original_new(wrapper, params)
        finally:
            _DRIVER_ALLOWED.reset(token)

    def deny_network(*args, **kwargs):
        raise RuntimeError('Python network access disabled in isolated PostgreSQL tests.')

    BaseDatabaseWrapper.ensure_connection = ensure
    BaseDatabaseWrapper.connect = connect
    DatabaseWrapper.get_new_connection = new
    psycopg.connect = driver_connect
    psycopg.Connection.connect = classmethod(lambda cls, *args, **kwargs: driver_connect(*args, **kwargs))
    async def deny_async(*args, **kwargs):
        raise RuntimeError('Async/direct psycopg connections are prohibited in these tests.')
    psycopg.AsyncConnection.connect = classmethod(deny_async)
    for method in ('connect', 'connect_ex', 'sendto', 'sendmsg'):
        if hasattr(socket.socket, method):
            setattr(socket.socket, method, deny_network)
    socket.create_connection = deny_network

from django.test.runner import DiscoverRunner


class DisposableDatabaseRunner(DiscoverRunner):
    """Reuse the approved database; never call PostgreSQL create/drop helpers."""
    def setup_databases(self, **kwargs):
        from django.db import connections
        from django.core.management import call_command
        try:
            validate_configuration(require_password=True)
            if not _EXECUTION_APPROVED:
                raise RuntimeError('Use the guarded module runner with explicit disposable-database confirmation.')
            if self.parallel != 1:
                raise RuntimeError('Parallel database cloning is disabled.')
            connection = connections['default']
            with connection.cursor() as cursor:
                cursor.execute('SELECT current_database(), current_user, inet_server_addr()::text, inet_server_port()')
                identity = cursor.fetchone()
                if (identity[:2] != (TARGET, EXPECTED['USER']) or identity[3:] != (5432,)
                        or not approved_server_address(identity[2])):
                    raise RuntimeError('Connected PostgreSQL identity does not match approved target.')
                cursor.execute("SELECT has_schema_privilege(current_user, 'public', 'USAGE'), has_schema_privilege(current_user, 'public', 'CREATE')")
                if cursor.fetchone() != (True, True):
                    raise RuntimeError('The local test role requires USAGE and CREATE on schema public.')
            # Explicit future --run consent authorizes migrations/flushes only here.
            call_command('migrate', database='default', interactive=False, verbosity=self.verbosity)
            connections['deletion_test'].creation.create_test_db(verbosity=self.verbosity, autoclobber=False)
            return None
        except Exception:
            # DiscoverRunner may not invoke teardown when setup itself fails.
            connections.close_all()
            raise

    def teardown_databases(self, old_config, **kwargs):
        from django.db import connections
        connections.close_all()  # No PostgreSQL DROP DATABASE, even after failure.


def main():
    global _EXECUTION_APPROVED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--confirm-disposable')
    parser.add_argument('labels', nargs='*')
    args = parser.parse_args()
    if args.preflight and (args.run or args.check_config):
        parser.error('--preflight cannot be combined with --run or --check-config')
    if args.run and (args.check_config or args.confirm_disposable != TARGET):
        parser.error('--run requires --confirm-disposable ' + TARGET)
    if any(label not in ALLOWED for label in args.labels):
        parser.error('Only the focused deletion regression labels are supported.')
    # libpq service/host/password environment defaults must not influence this run.
    for key in list(os.environ):
        if key.startswith('PG'):
            os.environ.pop(key)
    os.environ['DJANGO_SETTINGS_MODULE'] = SETTINGS
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    with TemporaryDirectory(prefix='verimeet-pg-tests-') as directory, ExitStack() as stack:
        from django.conf import settings
        settings.MEDIA_ROOT = directory + '/media'
        settings.PRIVATE_SIGNATURE_ROOT = directory + '/signatures'
        settings.PRIVATE_SNAPSHOT_ROOT = directory + '/snapshots'
        validate_configuration(require_password=args.run or args.preflight)
        # Block Python HTTP/email/storage networking. psycopg/libpq uses its C
        # transport; its explicit DSN and the identity check above guard the DB.
        stack.enter_context(patch('socket.socket.connect', side_effect=RuntimeError('External networking disabled in local PG tests')))
        stack.enter_context(patch('socket.create_connection', side_effect=RuntimeError('External networking disabled in local PG tests')))
        import django
        django.setup()
        validate_configuration(require_password=args.run or args.preflight)
        if 'core.settings' in sys.modules:
            raise RuntimeError('Production settings must not be imported by this runner.')
        if not args.run and not args.preflight:
            from django.core.management import call_command
            call_command('check', databases=[])
            print('Static configuration valid: 127.0.0.1:5432/' + TARGET + ' as ' + EXPECTED['USER'])
            print('No database connection or mutation performed. Role privileges not checked.')
            return 0
        _EXECUTION_APPROVED = True
        from django.db import connections
        try:
            if args.preflight:
                with connections['default'].cursor() as cursor:
                    cursor.execute('SELECT pg_backend_pid(), version()')
                    pid, version = cursor.fetchone()
                print('Local target/session identity verified; backend PID:', pid)
                print('Server major version:', version.split()[1])
                return 0
            return DisposableDatabaseRunner(verbosity=1, interactive=False, parallel=1).run_tests(
                args.labels or ['accounts.test_department_deletion'])
        finally:
            connections.close_all()
            _EXECUTION_APPROVED = False


if __name__ == '__main__':
    from accounts.run_postgres_department_tests import main as guarded_main
    sys.exit(guarded_main())
