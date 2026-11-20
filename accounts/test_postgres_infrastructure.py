"""Static/mock-only infrastructure tests: no database or service connections."""
import os
import subprocess
import sys
import unittest
from copy import deepcopy
from unittest.mock import MagicMock, patch
from accounts import run_postgres_department_tests as runner
from django.conf import settings
from django.db.backends.postgresql.base import DatabaseWrapper
from django.core.management import call_command
from django.test import override_settings
import psycopg


def setUpModule():
    if not runner._GUARDS_INSTALLED or not settings.configured or settings.SETTINGS_MODULE != runner.SETTINGS:
        raise unittest.SkipTest('Use python -m accounts.test_postgres_infrastructure')


class InfrastructureTests(unittest.TestCase):
    def setUp(self):
        self.auth = patch.object(runner, '_EXECUTION_APPROVED', False)
        self.auth.start()
        self.addCleanup(self.auth.stop)
        self.driver = patch.object(runner, '_RAW_CONNECT', side_effect=AssertionError('Real driver forbidden'))
        self.open = self.driver.start()
        self.addCleanup(self.driver.stop)

    def wrapper(self, alias='default'):
        return DatabaseWrapper(deepcopy(settings.DATABASES['default']), alias)

    def test_management_commands_denied(self):
        for command in ('migrate', 'flush'):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                call_command(command, interactive=False, verbosity=0)
        with self.assertRaises(RuntimeError):
            runner.DisposableDatabaseRunner(interactive=False).setup_databases()
        self.open.assert_not_called()

    def test_unauthorized_wrapper_denied(self):
        with self.assertRaises(RuntimeError): self.wrapper().ensure_connection()
        self.open.assert_not_called()

    def test_bad_alias_and_config_denied(self):
        with patch.object(runner, '_EXECUTION_APPROVED', True):
            for field, value in [('HOST','neon.invalid'), ('PORT','5433'), ('NAME','other'), ('USER','other')]:
                wrapper = self.wrapper()
                wrapper.settings_dict[field] = value
                with self.assertRaises(RuntimeError): wrapper.ensure_connection()
            with self.assertRaises(RuntimeError): self.wrapper('extra').ensure_connection()
            with patch.dict(settings.DATABASES, {'extra':deepcopy(settings.DATABASES['default'])}):
                with self.assertRaises(RuntimeError): runner.validate_configuration(True)
        self.open.assert_not_called()

    def test_independent_approved_wrappers(self):
        with patch.object(runner, '_EXECUTION_APPROVED', True):
            for _ in range(2): runner.validate_wrapper(self.wrapper())
        self.open.assert_not_called()

    def test_storage_overrides_preserve_connection_guards(self):
        wrapper = self.wrapper()
        wrapper.connection = MagicMock()
        with override_settings(PRIVATE_SIGNATURE_ROOT='mock-signatures', _EXECUTION_APPROVED=True):
            with override_settings(PRIVATE_SNAPSHOT_ROOT=None):
                self.assertIsNone(settings.SETTINGS_MODULE)
                with self.assertRaisesRegex(RuntimeError, 'explicit authorization'):
                    wrapper.ensure_connection()
                with patch.object(runner, '_EXECUTION_APPROVED', True):
                    wrapper.ensure_connection()
                    with patch.dict(wrapper.settings_dict, {'HOST': 'other.invalid'}):
                        with self.assertRaisesRegex(RuntimeError, 'unapproved local database'):
                            wrapper.ensure_connection()
        self.open.assert_not_called()

    def test_effective_database_overrides_rejected_for_existing_wrapper(self):
        wrapper = self.wrapper()
        wrapper.connection = MagicMock()
        with patch.object(runner, '_EXECUTION_APPROVED', True):
            for alias, field, value in (
                ('default', 'HOST', 'other.invalid'),
                ('default', 'PORT', '5433'),
                ('default', 'NAME', 'other'),
                ('default', 'USER', 'other'),
                ('default', 'ENGINE', 'django.db.backends.sqlite3'),
                ('deletion_test', 'NAME', 'other.sqlite3'),
                ('deletion_test', 'ENGINE', 'django.db.backends.postgresql'),
                ('deletion_test', 'OPTIONS', {'database': 'other.sqlite3'}),
            ):
                databases = deepcopy(settings.DATABASES)
                databases[alias][field] = value
                with self.subTest(alias=alias, field=field), override_settings(DATABASES=databases):
                    with self.assertRaisesRegex(RuntimeError, 'Refusing database target|Secondary alias'):
                        wrapper.ensure_connection()
            with override_settings(DATABASES={'default': deepcopy(settings.DATABASES['default'])}):
                with self.assertRaisesRegex(RuntimeError, 'database aliases'):
                    wrapper.ensure_connection()
            with override_settings(SETTINGS_MODULE='core.settings'):
                with self.assertRaisesRegex(RuntimeError, 'Unexpected test settings'):
                    wrapper.ensure_connection()
        self.open.assert_not_called()

    def test_driver_identity_and_error_redaction(self):
        params = dict(host='127.0.0.1', port='5432', dbname=runner.TARGET,
                      user=runner.EXPECTED['USER'], password='mock-secret',
                      connect_timeout=5, sslmode='disable',
                      options='-c lock_timeout=5000 -c statement_timeout=30000')
        with self.assertRaises(RuntimeError): psycopg.connect(**params)
        raw = MagicMock()
        raw.info.backend_pid = 123
        cursor = raw.cursor.return_value.__enter__.return_value
        with patch.object(runner, '_EXECUTION_APPROVED', True):
            marker = runner._DRIVER_ALLOWED.set(True)
            try:
                with patch.object(runner, '_RAW_CONNECT', return_value=raw):
                    cursor.fetchone.return_value = (runner.TARGET,runner.EXPECTED['USER'],'127.0.0.1',5432,123)
                    self.assertIs(psycopg.connect(**params), raw)
                    raw.rollback.assert_called_once()
                    for row in [('other',runner.EXPECTED['USER'],'127.0.0.1',5432,123),
                                (runner.TARGET,'other','127.0.0.1',5432,123),
                                (runner.TARGET,runner.EXPECTED['USER'],'127.0.0.2',5432,123),
                                (runner.TARGET,runner.EXPECTED['USER'],'127.0.0.1',5433,123),
                                (runner.TARGET,runner.EXPECTED['USER'],'127.0.0.1',5432,999)]:
                        cursor.fetchone.return_value = row
                        with self.assertRaises(RuntimeError): psycopg.connect(**params)
                    raw.close.assert_called()
                with patch.object(runner, '_RAW_CONNECT', side_effect=psycopg.OperationalError('password=mock-secret dsn=hidden')):
                    with self.assertRaises(RuntimeError) as caught: psycopg.connect(**params)
                    self.assertNotIn('mock-secret', str(caught.exception))
                    self.assertNotIn('hidden', str(caught.exception))
                with self.assertRaises(RuntimeError): psycopg.connect('postgresql://hidden')
            finally:
                runner._DRIVER_ALLOWED.reset(marker)

    def test_mock_authorized_runner_setup(self):
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = [
            (runner.TARGET, runner.EXPECTED['USER'], '127.0.0.1', 5432), (True, True)]
        aliases = {'default':connection, 'deletion_test':MagicMock()}
        with patch.object(runner, '_EXECUTION_APPROVED', True), patch('django.db.connections', aliases), patch('django.core.management.call_command') as command:
            runner.DisposableDatabaseRunner(parallel=1).setup_databases()
            command.assert_called_once_with('migrate',database='default',interactive=False,verbosity=1)
        self.open.assert_not_called()

    def test_static_main_cannot_connect(self):
        with patch('sys.argv', ['runner', '--check-config']):
            self.assertEqual(runner.main(), 0)
        self.open.assert_not_called()

    def test_imports_preserve_settings_without_initializing_django(self):
        subprocess.run([sys.executable, '-B', '-c', """
import importlib
import os
from unittest.mock import patch
from django.conf import settings

os.environ['DJANGO_SETTINGS_MODULE'] = 'unused.sentinel'
with patch('django.setup') as setup:
    for module in ('accounts.run_postgres_department_tests',
                   'accounts.test_postgres_infrastructure'):
        importlib.import_module(module)
        assert os.environ['DJANGO_SETTINGS_MODULE'] == 'unused.sentinel'
        assert not settings.configured
        setup.assert_not_called()
"""], check=True, timeout=30)

    def test_explicit_runner_initializes_guarded_settings(self):
        result = subprocess.run(
            [sys.executable, '-B', '-m', runner.__name__, '--check-config'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Static configuration valid', result.stdout)
        self.assertIn('No database connection or mutation performed', result.stdout)

    def test_python_network_guards(self):
        import socket
        sock = socket.socket()
        try:
            for method, args in [(sock.connect, (('127.0.0.1',5432),)),
                                 (sock.connect_ex, (('127.0.0.1',5432),)),
                                 (sock.sendto, (b'x',('127.0.0.1',5432)))]:
                with self.assertRaises(RuntimeError): method(*args)
        finally: sock.close()

    def test_sqlite_test_name_survives_django_setup_rewrite(self):
        from django.db.backends.sqlite3.base import DatabaseWrapper as SQLiteWrapper
        config = deepcopy(settings.DATABASES['deletion_test'])
        wrapper = SQLiteWrapper(config, alias='deletion_test')
        # Real Django name derivation; no connection or schema operations.
        derived = wrapper.creation._get_test_db_name()
        self.assertEqual(derived, runner.SQLITE_TEST_NAME)
        self.assertEqual(config['NAME'], derived)
        with patch.object(runner, '_EXECUTION_APPROVED', True), patch.dict(settings.DATABASES['deletion_test'], {'NAME':derived}):
            wrapper.settings_dict['NAME'] = derived
            runner.validate_configuration(True)
            runner.validate_wrapper(wrapper)
        self.open.assert_not_called()

    def test_secondary_alias_rejects_files_and_postgres(self):
        for name in ('other.sqlite3', 'file:other?mode=memory&cache=shared', ':memory:'):
            with patch.dict(settings.DATABASES['deletion_test'], {'NAME':name}):
                with self.assertRaises(RuntimeError): runner.validate_configuration(True)
        with patch.dict(settings.DATABASES['deletion_test'], {'ENGINE':'django.db.backends.postgresql'}):
            with self.assertRaises(RuntimeError): runner.validate_configuration(True)
        from django.db.backends.sqlite3.base import DatabaseWrapper as SQLiteWrapper
        config = deepcopy(settings.DATABASES['deletion_test'])
        config['OPTIONS'] = {'database': 'other.sqlite3'}
        with patch.object(runner, '_EXECUTION_APPROVED', True):
            with self.assertRaisesRegex(RuntimeError, 'unapproved alias or database'):
                SQLiteWrapper(config, alias='deletion_test').ensure_connection()
        self.open.assert_not_called()

    def test_setup_failure_closes_connections_and_propagates(self):
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = [
            (runner.TARGET, runner.EXPECTED['USER'], '127.0.0.1', 5432), (True, True)]
        aliases = MagicMock()
        secondary = MagicMock()
        aliases.__getitem__.side_effect = {'default':connection, 'deletion_test':secondary}.__getitem__
        secondary.creation.create_test_db.side_effect = RuntimeError('simulated alias setup failure')
        with patch.object(runner, '_EXECUTION_APPROVED', True), patch('django.db.connections', aliases), patch('django.core.management.call_command') as command:
            with self.assertRaisesRegex(RuntimeError, 'simulated alias setup failure'):
                runner.DisposableDatabaseRunner(parallel=1).setup_databases()
            command.assert_called_once_with('migrate',database='default',interactive=False,verbosity=1)
            aliases.close_all.assert_called_once()
        self.open.assert_not_called()


class PreflightDiagnosticTests(unittest.TestCase):
    def probe(self, raw):
        params = dict(host='127.0.0.1', port='5432', dbname=runner.TARGET,
                      user=runner.EXPECTED['USER'], password='mock-secret',
                      connect_timeout=5, sslmode='disable',
                      options='-c lock_timeout=5000 -c statement_timeout=30000')
        with patch.object(runner, '_EXECUTION_APPROVED', True), patch.object(runner, '_RAW_CONNECT', return_value=raw):
            token = runner._DRIVER_ALLOWED.set(True)
            try:
                return psycopg.connect(**params)
            finally:
                runner._DRIVER_ALLOWED.reset(token)

    def raw(self):
        raw = MagicMock()
        raw.info.backend_pid = 123
        raw.cursor.return_value.__enter__.return_value.fetchone.return_value = (
            runner.TARGET, runner.EXPECTED['USER'], '127.0.0.1', 5432, 123)
        return raw

    def assert_safe_failure(self, raw, category):
        import traceback
        with self.assertRaises(RuntimeError) as caught:
            self.probe(raw)
        text = ''.join(traceback.format_exception(caught.exception))
        self.assertIn(category, text)
        for secret in ('mock-secret', 'postgresql://', 'private-dsn', 'sensitive-details'):
            self.assertNotIn(secret, text)
        raw.close.assert_called_once()
        return str(caught.exception)

    def test_identity_query_failure(self):
        for stage in ('cursor', 'execute', 'fetchone', 'exit'):
            raw = self.raw()
            error = psycopg.OperationalError('sensitive-details private-dsn mock-secret')
            if stage == 'cursor': raw.cursor.side_effect = error
            elif stage == 'exit': raw.cursor.return_value.__exit__.side_effect = error
            else: getattr(raw.cursor.return_value.__enter__.return_value, stage).side_effect = error
            with self.subTest(stage=stage):
                message = self.assert_safe_failure(raw, 'Identity query failure')
                self.assertIn('exception=OperationalError', message)
                raw.rollback.assert_not_called()

    def test_identity_result_shape_and_types(self):
        correct = (runner.TARGET, runner.EXPECTED['USER'], '127.0.0.1', 5432, 123)
        cases = [None, (), list(correct), correct[:-1], correct + ('mock-secret',)]
        for index in range(5):
            row = list(correct)
            row[index] = b'mock-secret' if index < 3 else 'mock-secret'
            cases.append(tuple(row))
        cases.append(correct[:4] + (True,))
        for row in cases:
            with self.subTest(case=cases.index(row)):
                raw = self.raw()
                raw.cursor.return_value.__enter__.return_value.fetchone.return_value = row
                self.assert_safe_failure(raw, 'Identity result shape/type mismatch')
                raw.rollback.assert_not_called()

    def test_database_user_address_and_port_mismatch(self):
        for index, field in enumerate(('database', 'user', 'address', 'port')):
            raw = self.raw()
            row = list(raw.cursor.return_value.__enter__.return_value.fetchone.return_value)
            row[index] = 'mock-secret' if index < 3 else 5433
            raw.cursor.return_value.__enter__.return_value.fetchone.return_value = tuple(row)
            message = self.assert_safe_failure(raw, 'Database/user/address/port mismatch')
            self.assertIn('field=' + field, message)
            raw.rollback.assert_not_called()

    def test_backend_pid_mismatch_and_accessor_failure(self):
        from unittest.mock import PropertyMock
        raw = self.raw()
        raw.info.backend_pid = 999
        self.assert_safe_failure(raw, 'Backend PID mismatch')
        raw = self.raw()
        with patch.object(type(raw.info), 'backend_pid', new_callable=PropertyMock, create=True,
                          side_effect=RuntimeError('sensitive-details')):
            self.assert_safe_failure(raw, 'Backend PID mismatch')

    def test_identity_probe_rollback_failure(self):
        raw = self.raw()
        raw.rollback.side_effect = psycopg.OperationalError('sensitive-details mock-secret')
        self.assert_safe_failure(raw, 'Identity-probe rollback failure')
        raw.rollback.assert_called_once()

    def test_sqlstate_validation_and_close_failure(self):
        class ProbeFailure(Exception):
            sqlstate = '08006'
        raw = self.raw()
        raw.cursor.side_effect = ProbeFailure('sensitive-details')
        message = self.assert_safe_failure(raw, 'Identity query failure')
        self.assertIn('SQLSTATE=08006', message)
        raw = self.raw()
        error = ProbeFailure('sensitive-details')
        error.sqlstate = 'mock-secret'
        raw.cursor.side_effect = error
        raw.close.side_effect = RuntimeError('private-dsn sensitive-details')
        message = self.assert_safe_failure(raw, 'Identity query failure')
        self.assertIn('connection close failed', message)
        self.assertNotIn('SQLSTATE=', message)

    def test_successful_probe_unchanged(self):
        raw = self.raw()
        self.assertIs(self.probe(raw), raw)
        raw.rollback.assert_called_once()
        raw.close.assert_not_called()


    def test_exact_ipv4_address_normalization(self):
        from ipaddress import IPv4Address, IPv6Address
        for address in ('127.0.0.1', '127.0.0.1/32', IPv4Address('127.0.0.1')):
            with self.subTest(form=type(address).__name__):
                raw = self.raw()
                raw.cursor.return_value.__enter__.return_value.fetchone.return_value = (
                    runner.TARGET, runner.EXPECTED['USER'], address, 5432, 123)
                self.assertIs(self.probe(raw), raw)
                raw.close.assert_not_called()
        for address in ('127.0.0.2', '127.1.2.3', '127.0.0.1/24', '0.0.0.0',
                        '::1', '::ffff:127.0.0.1', 'localhost', '127.0.0.1:5432',
                        '127.0.0.1/0', ' 127.0.0.1', IPv4Address('127.0.0.2'),
                        IPv6Address('::1')):
            raw = self.raw()
            raw.cursor.return_value.__enter__.return_value.fetchone.return_value = (
                runner.TARGET, runner.EXPECTED['USER'], address, 5432, 123)
            message = self.assert_safe_failure(raw, 'Database/user/address/port mismatch')
            self.assertIn('field=address', message)

    def test_runner_setup_accepts_exact_host_mask(self):
        connection = MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = [
            (runner.TARGET, runner.EXPECTED['USER'], '127.0.0.1/32', 5432), (True, True)]
        aliases = {'default':connection, 'deletion_test':MagicMock()}
        with patch.object(runner, '_EXECUTION_APPROVED', True), patch('django.db.connections', aliases), patch('django.core.management.call_command') as command:
            runner.DisposableDatabaseRunner(parallel=1).setup_databases()
            command.assert_called_once_with('migrate',database='default',interactive=False,verbosity=1)


if __name__ == '__main__':
    import django

    os.environ['DJANGO_SETTINGS_MODULE'] = runner.SETTINGS
    os.environ['VERIMEET_PG_TEST_PASSWORD'] = 'mock-only-password'
    django.setup()
    unittest.main()
