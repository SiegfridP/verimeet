"""Confirmed destruction regressions; never uses deployment resources."""
from unittest.mock import patch
from django.contrib import admin
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from .models import User, Department, Membership
from .department_deletion import prepare, delete_departments, scoped, SALT
from meetings.models import Meeting, Attendance, AuditLog, HistoricalRoster, SigningVisualSnapshot, VerificationQR
from meetings.evidence_objects import PrivateEvidenceObject


class DepartmentDeletionTests(TransactionTestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username='global', is_superuser=True, is_staff=True, public_key='test')
        self.officer = User.objects.create_user(username='officer', public_key='test')
        self.department = Department.objects.create(name='Delete me')
        self.other = Department.objects.create(name='Keep me')
        Membership.objects.create(user=self.officer, department=self.department)

    def token(self, ids=None, actor=None):
        return prepare(actor or self.actor, ids or [self.department.pk])[2]

    def execute(self, ids=None, **kwargs):
        ids = ids or [self.department.pk]
        values = dict(confirmation=self.token(ids), typed='DELETE', reason='Test cleanup')
        values.update(kwargs)
        return delete_departments(self.actor, ids, **values)

    def protected(self, status='Archived'):
        meeting = Meeting.objects.create(department=self.department, title='Evidence', status=status)
        attendance = Attendance.objects.create(meeting=Meeting.objects.create(department=self.department, title='Draft'), user=self.officer)
        # Fixture represents existing signed evidence, without calling signing services.
        Attendance.objects.filter(pk=attendance.pk).update(has_signed=True, cryptographic_signature='signature')
        SigningVisualSnapshot.objects.create(attendance=attendance, storage_identifier='a'*32,
            content_sha256='b'*64, byte_length=1, width=1, height=1)
        for revoked in (False, True):
            VerificationQR.objects.create(attendance=attendance, token_hash=str(revoked), encrypted_token='test', is_revoked=revoked)
        return attendance

    def test_empty_superuser_and_audit(self):
        self.execute()
        self.assertFalse(Department.objects.filter(pk=self.department.pk).exists())
        self.assertTrue(Department.objects.filter(pk=self.other.pk).exists())
        event = AuditLog.objects.get(event_type='department.deleted')
        self.assertIsNone(event.department_id)
        self.assertEqual(event.metadata['reason'], 'Test cleanup')
        self.assertEqual(AuditLog.objects.filter(event_type='membership.removed').count(), 1)
        self.assertTrue(User.objects.filter(pk=self.officer.pk).exists())

    def test_application_global_admin(self):
        User.objects.filter(pk=self.actor.pk).update(is_superuser=False, is_admin=True)
        self.actor.refresh_from_db()
        self.execute()

    def test_all_lifecycles_and_evidence_retained(self):
        from hashlib import sha256
        obj = PrivateEvidenceObject.objects.create(key='snapshots/'+'a'*32+'.png', data=b'x', content_sha256=sha256(b'x').hexdigest())
        self.protected()
        Meeting.objects.create(department=self.department, title='Finished', status='Finished')
        self.execute()
        self.assertFalse(Attendance.objects.exists())
        self.assertFalse(SigningVisualSnapshot.objects.exists())
        self.assertFalse(HistoricalRoster.objects.exists())
        self.assertFalse(VerificationQR.objects.exists())
        self.assertTrue(PrivateEvidenceObject.objects.filter(pk=obj.pk).exists())

    def test_draft_unsigned(self):
        meeting = Meeting.objects.create(department=self.department, title='Draft')
        Attendance.objects.create(meeting=meeting, user=self.officer)
        self.execute()

    def test_direct_orm_rejected(self):
        for operation in (lambda: self.department.delete(), lambda: Department.objects.all().delete()):
            with transaction.atomic():
                with self.assertRaises(PermissionDenied): operation()
        self.assertEqual(Department.objects.count(), 2)

    def test_unauthorized_roles_and_inactive(self):
        for actor in (self.officer, User.objects.create_user(username='staff', is_staff=True, public_key='test')):
            with self.assertRaises(PermissionDenied): prepare(actor, [self.department.pk])
        User.objects.filter(pk=self.actor.pk).update(is_superuser=False)
        with self.assertRaises(PermissionDenied): self.execute(confirmation='invalid')

    def test_demoted_after_confirmation(self):
        token = self.token()
        User.objects.filter(pk=self.actor.pk).update(is_superuser=False)
        with self.assertRaises(PermissionDenied): self.execute(confirmation=token)

    def test_invalid_confirmation_fields(self):
        for changes in ({'typed':''}, {'reason':''}, {'confirmation':''}, {'confirmation':'forged'}):
            with self.assertRaises(PermissionDenied): self.execute(**changes)

    def test_expired_cross_actor_database_and_targets(self):
        payload = signing.loads(self.token(), salt=SALT)
        for changes in ({'actor':self.officer.pk}, {'using':'other'}, {'ids':[self.other.pk]}):
            modified = dict(payload, **changes)
            with self.assertRaises(PermissionDenied): self.execute(confirmation=signing.dumps(modified,salt=SALT))
        token = self.token()
        with patch('django.core.signing.time.time', return_value=10**12):
            with self.assertRaises(PermissionDenied): self.execute(confirmation=token)

    def test_stale_inventory(self):
        token = self.token()
        Meeting.objects.create(department=self.department, title='New')
        with self.assertRaises(PermissionDenied): self.execute(confirmation=token)

    def test_replay(self):
        token = self.token()
        ids = [self.department.pk]
        self.execute(confirmation=token)
        with self.assertRaises(PermissionDenied):
            delete_departments(self.actor, ids, confirmation=token, typed='DELETE', reason='Again')

    def test_audit_failure_bulk_rollback(self):
        ids = [self.department.pk, self.other.pk]
        token = self.token(ids)
        with patch('accounts.department_deletion.record', side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError): self.execute(ids, confirmation=token)
        self.assertEqual(Department.objects.count(), 2)
        self.assertFalse(AuditLog.objects.exists())
        self.assertFalse(scoped(self.department, 'default'))

    def test_descendant_failure_rollback_and_scope_cleanup(self):
        self.protected()
        token = self.token()
        from django.db.models.query import QuerySet
        original_delete = QuerySet.delete
        def fail_second(query):
            if query.model is HistoricalRoster:
                raise RuntimeError('roster deletion failed after snapshot removal')
            return original_delete(query)
        with patch.object(QuerySet, 'delete', fail_second):
            with self.assertRaises(RuntimeError): self.execute(confirmation=token)
        self.assertTrue(SigningVisualSnapshot.objects.exists())
        self.assertFalse(AuditLog.objects.exists())
        with transaction.atomic():
            with self.assertRaises((PermissionDenied, ProtectedError)): self.department.delete()

    def test_unrelated_protections(self):
        attendance = self.protected()
        for obj in (attendance, attendance.meeting, self.officer, SigningVisualSnapshot.objects.get()):
            with self.assertRaises((PermissionDenied, __import__('django.db.models',fromlist=['ProtectedError']).ProtectedError)):
                with transaction.atomic(): obj.delete()

    def test_application_confirmation(self):
        self.client.force_login(self.actor)
        url = reverse('delete_department', args=[self.department.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code,200)
        self.assertContains(response, 'Type DELETE')
        response = self.client.post(url, dict(execute_deletion='yes',confirmation=response.context['confirmation'],typed='DELETE',reason='Cleanup'))
        self.assertEqual(response.status_code,302)
        self.assertFalse(Department.objects.filter(pk=self.department.pk).exists())

    def test_admin_individual(self):
        self.protected()
        self.client.force_login(self.actor)
        url = reverse('admin:accounts_department_delete', args=[self.department.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code,200)
        response = self.client.post(url,dict(execute_deletion='yes', confirmation=response.context['confirmation'],typed='DELETE',reason='Cleanup'))
        self.assertEqual(response.status_code,302)

    def test_admin_bulk(self):
        self.client.force_login(self.actor)
        url = reverse('admin:accounts_department_changelist')
        data = {'action':'delete_departments_confirmed','_selected_action':[self.department.pk,self.other.pk]}
        response = self.client.post(url,data)
        self.assertEqual(response.status_code,200)
        data.update(execute_deletion='yes',confirmation=response.context['confirmation'],typed='DELETE',reason='Cleanup')
        self.assertEqual(self.client.post(url,data).status_code,302)
        self.assertFalse(Department.objects.exists())

    def test_officer_http_and_admin_actions(self):
        from .test_fixtures import signature_storage, complete_onboarding
        signature_storage(self)
        complete_onboarding(self.officer)
        self.client.force_login(self.officer)
        self.assertEqual(self.client.get(reverse('delete_department',args=[self.department.pk])).status_code,403)
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        from django.test import RequestFactory
        request=RequestFactory().get('/'); request.user=self.actor
        self.assertNotIn('delete_selected',admin.site._registry[Department].get_actions(request))

    def test_inactive_anonymous_and_staff_permissions(self):
        from django.contrib.auth.models import AnonymousUser, Permission
        from django.db import models
        staff = User.objects.create_user(username='permitted', is_staff=True, public_key='test')
        staff.user_permissions.add(Permission.objects.get(codename='delete_department'))
        for actor in (staff, AnonymousUser()):
            with self.assertRaises(PermissionDenied): prepare(actor, [self.department.pk])
        token = self.token()
        models.QuerySet.update(User.objects.filter(pk=self.actor.pk), is_active=False)
        with self.assertRaises(PermissionDenied): self.execute(confirmation=token)

    def test_bulk_later_audit_failure_rolls_back(self):
        from .audit import record
        ids = [self.department.pk, self.other.pk]
        token = self.token(ids)
        def fail(actor, event_type, target, *args, **kwargs):
            if event_type == 'department.deleted' and target.pk == self.other.pk:
                raise RuntimeError('second audit failed')
            return record(actor, event_type, target, *args, **kwargs)
        with patch('accounts.department_deletion.record', side_effect=fail):
            with self.assertRaises(RuntimeError): self.execute(ids, confirmation=token)
        self.assertEqual(Department.objects.count(), 2)
        self.assertFalse(AuditLog.objects.exists())

    def test_scope_rejects_unrelated_objects(self):
        from . import department_deletion as service
        original = service.record
        def inspect(*args, **kwargs):
            self.assertFalse(scoped(self.other, 'default'))
            self.assertFalse(scoped(self.department, 'other'))
            return original(*args, **kwargs)
        with patch('accounts.department_deletion.record', side_effect=inspect): self.execute()
        self.assertFalse(scoped(self.department, 'default'))

    def test_direct_admin_hooks_and_forged_http(self):
        from django.test import RequestFactory, Client
        request = RequestFactory().post('/'); request.user = self.actor
        model_admin = admin.site._registry[Department]
        with self.assertRaises(PermissionDenied): model_admin.delete_model(request, self.department)
        with self.assertRaises(PermissionDenied): model_admin.delete_queryset(request, Department.objects.all())
        self.client.force_login(self.actor)
        url = reverse('delete_department', args=[self.department.pk])
        self.assertEqual(self.client.post(url, {'execute_deletion':'yes','typed':'DELETE','reason':'Bad','confirmation':'forged'}).status_code,400)
        csrf = Client(enforce_csrf_checks=True); csrf.force_login(self.actor)
        self.assertEqual(csrf.post(url).status_code,403)

    def test_ap_and_officer_get_post_reach_authorization(self):
        from .test_fixtures import signature_storage, complete_onboarding
        signature_storage(self)
        complete_onboarding(self.officer)
        token = self.token()
        url = reverse('delete_department', args=[self.department.pk])
        for role in ('O', 'AP'):
            Membership.objects.filter(user=self.officer).update(role=role)
            self.client.force_login(self.officer)
            self.assertEqual(self.client.get(url).status_code, 403)
            self.assertEqual(self.client.post(url, dict(execute_deletion='yes',
                confirmation=token, typed='DELETE', reason='Unauthorized')).status_code, 403)
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())

    def test_expiration_after_inventory_in_service_and_interfaces(self):
        from . import department_deletion as service
        original = service.inventory
        import time
        now = time.time()
        for endpoint in ('service', 'application', 'admin', 'bulk'):
            token = self.token()
            with patch('django.core.signing.time.time', return_value=now) as clock:
                def delayed(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if kwargs.get('lock'): clock.return_value = now + 700
                    return result
                with patch.object(service, 'inventory', side_effect=delayed):
                    if endpoint == 'service':
                        with self.assertRaises(PermissionDenied): self.execute(confirmation=token)
                    else:
                        self.client.force_login(self.actor)
                        data = dict(execute_deletion='yes',confirmation=token,typed='DELETE',reason='Cleanup')
                        url = reverse('delete_department',args=[self.department.pk])
                        if endpoint == 'admin': url = reverse('admin:accounts_department_delete',args=[self.department.pk])
                        if endpoint == 'bulk':
                            url = reverse('admin:accounts_department_changelist')
                            data.update(action='delete_departments_confirmed', _selected_action=[self.department.pk])
                        self.assertEqual(self.client.post(url,data).status_code,400)
            self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
            self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())

    def test_lock_failure_rolls_back_and_rejects_replay(self):
        from django.db import OperationalError
        from . import department_deletion as service
        class LockFailure(Exception): sqlstate = '40P01'
        error = OperationalError('sensitive database message')
        error.__cause__ = LockFailure()
        token = self.token()
        with patch.object(service, 'record', side_effect=error):
            with self.assertRaisesMessage(PermissionDenied, 'rolled back'): self.execute(confirmation=token)
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())
        with self.assertRaisesMessage(PermissionDenied, 'already used'): self.execute(confirmation=token)

    def test_unexpected_database_error_propagates(self):
        from django.db import OperationalError
        with patch('accounts.department_deletion.record', side_effect=OperationalError('unexpected')):
            with self.assertRaises(OperationalError): self.execute()

    def test_deterministic_lock_order(self):
        from django.db import connection
        meeting = Meeting.objects.create(department=self.department, title='Lock target')
        Attendance.objects.create(meeting=meeting, user=self.officer)
        writes = []
        def inspect(execute, sql, params, many, context):
            if sql.startswith('UPDATE "accounts_department"'): writes.append(('department', params[-1]))
            if sql.startswith('UPDATE "meetings_meeting"'): writes.append(('meeting', params[-1]))
            return execute(sql, params, many, context)
        from django.db.models.query import QuerySet
        original_lock = QuerySet.select_for_update
        locks = []
        def lock(query, *args, **kwargs):
            locks.append(query.model)
            return original_lock(query, *args, **kwargs)
        with connection.execute_wrapper(inspect), patch.object(QuerySet, 'select_for_update', lock): self.execute()
        self.assertLess(locks.index(Department), locks.index(Meeting))
        self.assertLess(locks.index(Meeting), locks.index(Attendance))
        self.assertEqual(writes[:3], [('department', self.department.pk), ('department', self.other.pk), ('meeting', meeting.pk)])

    def test_lock_timeout_http_requires_new_confirmation(self):
        from django.db import OperationalError
        class Timeout(Exception): sqlstate = '55P03'
        self.client.force_login(self.actor)
        for name in ('delete_department', 'admin:accounts_department_delete'):
            token = self.token()
            error = OperationalError('private database details')
            error.__cause__ = Timeout()
            url = reverse(name, args=[self.department.pk])
            with patch('accounts.department_deletion.record', side_effect=error):
                response = self.client.post(url, dict(execute_deletion='yes',
                    confirmation=token, typed='DELETE', reason='Cleanup'))
            self.assertEqual(response.status_code, 400)
            self.assertContains(response, 'rolled back', status_code=400)
            self.assertNotContains(response, 'private database details', status_code=400)
            self.assertNotEqual(response.context['confirmation'], token)
            with self.assertRaises(PermissionDenied): self.execute(confirmation=token)
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())

    def test_outer_transaction_rejected_before_any_deletion_attempt(self):
        token = self.token()
        with patch('accounts.department_deletion.record') as record:
            with self.assertRaises(RuntimeError):
                with transaction.atomic():
                    self.execute(confirmation=token)
            record.assert_not_called()
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        self.assertFalse(AuditLog.objects.exists())
        # Rejection is before execution: the token was not consumed or failed.
        self.execute(confirmation=token)

    def test_collector_relationship_manifest_and_unreviewed_model(self):
        from . import department_deletion as service
        from django.db import models
        from django.test.utils import isolate_apps
        self.assertEqual(service.deletion_relations(), service.REVIEWED_RELATIONS)
        # Introduce a real reverse relation in an isolated app registry.
        with isolate_apps('accounts'):
            class Parent(models.Model):
                class Meta: app_label = 'accounts'
            class Unreviewed(models.Model):
                parent = models.ForeignKey(Parent, on_delete=models.CASCADE)
                class Meta: app_label = 'accounts'
            with patch.object(service, 'Department', Parent):
                self.assertIn(('accounts.Parent', 'accounts.Unreviewed', 'parent', 'CASCADE'), service.deletion_relations())
                with self.assertRaisesMessage(PermissionDenied, 'inventory review'):
                    service.validate_deletion_relations()

    def test_bulk_confirmation_displays_selection_count(self):
        self.client.force_login(self.actor)
        response = self.client.post(reverse('admin:accounts_department_changelist'), {
            'action':'delete_departments_confirmed',
            '_selected_action':[self.department.pk, self.other.pk]})
        self.assertContains(response, 'Selected Departments: <strong>2</strong>')

    def test_concurrent_attempt_during_failure_publication(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from django.db import OperationalError, connections
        from django.db.models.query import QuerySet
        for state in ('40P01', '55P03'):
            token = self.token()
            publishing, release = Event(), Event()
            class DriverFailure(Exception): sqlstate = state
            error = OperationalError('simulated PostgreSQL lock failure')
            error.__cause__ = DriverFailure()
            original_create = QuerySet.create
            def delayed_create(query, **kwargs):
                if query.model is AuditLog and kwargs.get('event_type') == 'department.deletion_failed':
                    publishing.set()
                    if not release.wait(10): raise AssertionError('publication barrier timed out')
                return original_create(query, **kwargs)
            def attempt():
                try:
                    with self.assertRaisesMessage(PermissionDenied, 'rolled back'):
                        delete_departments(self.actor, [self.department.pk], confirmation=token,
                                           typed='DELETE', reason='Concurrent test')
                finally:
                    connections.close_all()
            with patch('accounts.department_deletion.record', side_effect=error), patch.object(QuerySet, 'create', delayed_create):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    first = executor.submit(attempt)
                    try:
                        self.assertTrue(publishing.wait(10))
                        # First transaction is rolled back, marker not yet published.
                        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())
                        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
                        with self.assertRaisesMessage(PermissionDenied, 'already being processed'):
                            delete_departments(self.actor, [self.department.pk], confirmation=token,
                                               typed='DELETE', reason='Replay')
                    finally:
                        release.set()
                    first.result(timeout=10)
            # The local operation lock was released, but durable replay state remains.
            with self.assertRaisesMessage(PermissionDenied, 'already used'):
                self.execute(confirmation=token)
            self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())

    def test_operation_lock_cleanup_and_database_isolation(self):
        from .department_deletion import _operation_lock
        from django.db import connections
        for fail in (False, True):
            try:
                with _operation_lock(connections['default'], 'test-operation'):
                    with self.assertRaises(PermissionDenied):
                        with _operation_lock(connections['default'], 'test-operation'): pass
                    with _operation_lock(connections['deletion_test'], 'test-operation'): pass
                    if fail: raise ValueError('body failed')
            except ValueError: pass
            with _operation_lock(connections['default'], 'test-operation'): pass

    @override_settings(DEPARTMENT_DELETION_SESSION_AFFINITY={'default':'direct', 'other':'session'})
    def test_postgresql_session_lock_protocol_and_cleanup(self):
        from unittest.mock import MagicMock
        from .department_deletion import _operation_lock
        def connection(rows, alias='default'):
            conn = MagicMock(vendor='postgresql', alias=alias, settings_dict={'HOST':'localhost'})
            conn.connection.closed = False
            conn.connection.info.backend_pid = 123
            cursor = conn.cursor.return_value.__enter__.return_value
            cursor.fetchone.side_effect = rows
            return conn, cursor
        for fail in (False, True):
            conn, cursor = connection([(123, True), (123,), (123, True)])
            try:
                with _operation_lock(conn, 'operation') as check:
                    check()
                    if fail: raise ValueError('body failed')
            except ValueError: pass
            calls = cursor.execute.call_args_list
            self.assertIn('pg_try_advisory_lock', calls[0].args[0])
            self.assertIn('CASE WHEN pg_backend_pid()', calls[-1].args[0])
            self.assertEqual(calls[0].args[1][0], calls[-1].args[1][1])
            self.assertEqual(calls[-1].args[1][0], 123)
            conn.close.assert_not_called()
            conn.connection.close.assert_not_called()
        conn, cursor = connection([(123, False)])
        with self.assertRaises(PermissionDenied):
            with _operation_lock(conn, 'operation'): self.fail('must not execute')
        self.assertEqual(cursor.execute.call_count, 1)
        for rows in ([(456, True)], [(123, True), (456, True)], [(123, True), (123, False)]):
            conn, cursor = connection(rows)
            raw = conn.connection
            with self.assertRaises(RuntimeError):
                with _operation_lock(conn, 'operation'): pass
            conn.close.assert_called()
            raw.close.assert_called()
        for fail_at in ('acquire', 'release'):
            conn, cursor = connection([(123, True)])
            cursor.execute.side_effect = [RuntimeError('acquire')] if fail_at == 'acquire' else [None, RuntimeError('release')]
            with self.assertRaises(RuntimeError):
                with _operation_lock(conn, 'operation'): pass
            conn.close.assert_called()
        for change in ('replaced', 'closed', 'driver_pid', 'server_pid'):
            conn, cursor = connection([(123, True), (456,)])
            raw = conn.connection
            with self.assertRaises(RuntimeError):
                with _operation_lock(conn, 'operation') as check:
                    if change == 'replaced': conn.connection = MagicMock()
                    if change == 'closed': raw.closed = True
                    if change == 'driver_pid': raw.info.backend_pid = 456
                    check()
            raw.close.assert_called()
            conn.close.assert_called()
        keys = []
        for alias in ('default', 'other'):
            conn, cursor = connection([(123, True), (123, True)], alias)
            with _operation_lock(conn, 'operation'): pass
            keys.append(cursor.execute.call_args_list[0].args[1][0])
        self.assertNotEqual(*keys)
        for host, alias in (('ep-example-pooler.neon.tech', 'default'), ('localhost', 'undeclared')):
            conn, cursor = connection([], alias)
            conn.settings_dict['HOST'] = host
            with self.assertRaisesMessage(RuntimeError, 'explicitly configured'):
                with _operation_lock(conn, 'operation'): pass
            conn.cursor.assert_not_called()

    @override_settings(DEPARTMENT_DELETION_SESSION_AFFINITY={'default':'direct'})
    def test_cleanup_invalidates_real_django_wrapper_without_reconnecting(self):
        from unittest.mock import MagicMock
        from django.db.backends.postgresql.base import DatabaseWrapper
        from .department_deletion import _operation_lock
        # Use Django's real close() semantics, including its early-return path.
        for atomic in (False, True):
            for already_closed in (False, True):
                conn = DatabaseWrapper({'HOST':'localhost', 'OPTIONS':{}}, alias='default')
                conn.vendor = 'postgresql'
                original, replacement = MagicMock(), MagicMock()
                original.closed = False
                original.info.backend_pid = 123
                conn.connection = original
                cursor = MagicMock()
                cursor.__enter__.return_value = cursor
                cursor.fetchone.return_value = (123, True)
                with patch.object(conn, 'cursor', return_value=cursor) as get_cursor, patch.object(conn, 'connect') as connect:
                    with self.assertRaisesMessage(RuntimeError, 'session changed'):
                        with _operation_lock(conn, 'operation') as check:
                            conn.connection = replacement
                            conn.in_atomic_block = atomic
                            conn.closed_in_transaction = already_closed
                            check()
                    original.close.assert_called_once()
                    replacement.close.assert_called()
                    self.assertIsNone(conn.connection)
                    self.assertEqual(conn.run_on_commit, [])
                    self.assertTrue(conn.errors_occurred)
                    if atomic:
                        self.assertTrue(conn.closed_in_transaction)
                        self.assertTrue(conn.needs_rollback)
                    self.assertEqual(get_cursor.call_count, 1)
                    connect.assert_not_called()

    @override_settings(DEPARTMENT_DELETION_SESSION_AFFINITY={'default':'direct'})
    def test_cleanup_preserves_original_and_replacement_close_errors(self):
        from unittest.mock import MagicMock
        from .department_deletion import _operation_lock
        conn = MagicMock(vendor='postgresql', alias='default', settings_dict={'HOST':'localhost'})
        conn.in_atomic_block = False
        original = conn.connection
        original.closed = False
        original.info.backend_pid = 123
        original.close.side_effect = RuntimeError('original session close failed')
        replacement = MagicMock()
        replacement.close.side_effect = ValueError('replacement close failed')
        conn.close.side_effect = OSError('wrapper close failed')
        cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (123, True)
        with self.assertRaises(ExceptionGroup) as caught:
            with _operation_lock(conn, 'operation') as check:
                conn.connection = replacement
                check()
        self.assertEqual([str(exc) for exc in caught.exception.exceptions], [
            'original session close failed', 'replacement close failed', 'wrapper close failed'])
        original.close.assert_called_once()
        replacement.close.assert_called_once()
        conn.close.assert_called_once()
        self.assertIsNone(conn.connection)
        self.assertEqual(conn.cursor.call_count, 1)
        conn.connect.assert_not_called()
        conn.ensure_connection.assert_not_called()


class DepartmentDeletionAliasTests(TransactionTestCase):
    databases = {'default', 'deletion_test'}

    def test_success_and_rollback_stay_on_alias(self):
        alias = 'deletion_test'
        actor = User.objects.db_manager(alias).create_user(username='alias-admin', is_admin=True, public_key='test')
        department = Department.objects.using(alias).create(name='Alias target')
        token = prepare(actor, [department.pk], alias)[2]
        args = dict(confirmation=token, typed='DELETE', reason='Alias test', using=alias)
        with patch('accounts.department_deletion.record', side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError): delete_departments(actor, [department.pk], **args)
        self.assertTrue(Department.objects.using(alias).filter(pk=department.pk).exists())
        self.assertFalse(AuditLog.objects.using(alias).exists())
        delete_departments(actor, [department.pk], **args)
        event = AuditLog.objects.using(alias).get(event_type='department.deleted')
        self.assertIsNone(event.department_id)
        self.assertFalse(Department.objects.using(alias).exists())
        self.assertFalse(AuditLog.objects.using('default').exists())


class DepartmentDeletionTransactionBoundaryTests(TransactionTestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username='transaction-admin', is_admin=True, public_key='test')
        self.department = Department.objects.create(name='Transaction target')
        self.token = prepare(self.actor, [self.department.pk])[2]

    def execute(self):
        delete_departments(self.actor, [self.department.pk], confirmation=self.token,
                           typed='DELETE', reason='Transaction boundary test')

    def test_failure_marker_commits_and_survives_subsequent_rollback(self):
        from django.db import OperationalError, connection
        class Deadlock(Exception): sqlstate = '40P01'
        error = OperationalError('simulated deadlock')
        error.__cause__ = Deadlock()
        with patch('accounts.department_deletion.record', side_effect=error):
            with self.assertRaises(PermissionDenied): self.execute()
        self.assertTrue(connection.get_autocommit())
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.assertTrue(AuditLog.objects.filter(event_type='department.deletion_failed').exists())
                raise RuntimeError('caller rollback')
        self.assertTrue(AuditLog.objects.filter(event_type='department.deletion_failed').exists())
        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        with self.assertRaisesMessage(PermissionDenied, 'already used'): self.execute()

    def test_enclosing_atomic_rejected_without_failure_marker(self):
        with self.assertRaisesMessage(RuntimeError, 'ownership'):
            with transaction.atomic(): self.execute()
        self.assertFalse(AuditLog.objects.exists())
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())

    def test_manual_transaction_rejected(self):
        from django.db import connection
        connection.set_autocommit(False)
        try:
            with self.assertRaisesMessage(RuntimeError, 'ownership'): self.execute()
        finally:
            connection.rollback()
            connection.set_autocommit(True)
        self.assertFalse(AuditLog.objects.exists())
