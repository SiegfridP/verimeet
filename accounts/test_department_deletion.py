"""Confirmed destruction regressions; never uses deployment resources."""
from contextlib import nullcontext
from unittest.mock import patch
from django.contrib import admin
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from .models import User, Department, Membership
from .department_deletion import (
    CLAIM_EVENT, SALT, DepartmentDeletionUnavailable, delete_departments, prepare, scoped,
)
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
        retained = Membership.objects.create(user=self.officer, department=self.other)
        token = self.token()
        ids = [self.department.pk]
        self.execute(confirmation=token)
        with self.assertRaisesMessage(PermissionDenied, 'already used'):
            delete_departments(self.actor, ids, confirmation=token, typed='DELETE', reason='Again')
        events = AuditLog.objects.filter(metadata__operation_id=signing.loads(token, salt=SALT)['operation'])
        self.assertCountEqual(events.values_list('event_type', flat=True), [CLAIM_EVENT, 'department.deleted'])
        self.assertTrue(Membership.objects.filter(pk=retained.pk).exists())
        self.assertEqual(User.objects.filter(pk__in=[self.actor.pk, self.officer.pk]).count(), 2)

    def test_audit_failure_bulk_rollback(self):
        ids = [self.department.pk, self.other.pk]
        token = self.token(ids)
        with patch('accounts.department_deletion.record', side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError): self.execute(ids, confirmation=token)
        self.assertEqual(Department.objects.count(), 2)
        self.assertEqual(list(AuditLog.objects.values_list('event_type', flat=True)), [CLAIM_EVENT])
        with self.assertRaisesMessage(PermissionDenied, 'already used'):
            self.execute(ids, confirmation=token)
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
        self.assertEqual(list(AuditLog.objects.values_list('event_type', flat=True)), [CLAIM_EVENT])
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
        self.assertEqual(list(AuditLog.objects.values_list('event_type', flat=True)), [CLAIM_EVENT])

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
            operation = signing.loads(token, salt=SALT)['operation']
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
                        self.assertEqual(AuditLog.objects.filter(event_type=CLAIM_EVENT,
                                         metadata__operation_id=operation).count(), 1)
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
        owner = connections['default']
        contender = owner
        if owner.vendor == 'postgresql':
            # A same-session advisory lock is reentrant. Use Django's copied
            # wrapper to open a second session on the same guarded alias.
            contender = owner.copy()
            self.addCleanup(contender.close)
            with owner.cursor() as cursor:
                cursor.execute('SELECT pg_backend_pid()')
                owner_pid, = cursor.fetchone()
            with contender.cursor() as cursor:
                cursor.execute('SELECT pg_backend_pid()')
                contender_pid, = cursor.fetchone()
            self.assertIsNot(owner.connection, contender.connection)
            self.assertEqual(owner_pid, owner.connection.info.backend_pid)
            self.assertEqual(contender_pid, contender.connection.info.backend_pid)
            self.assertNotEqual(owner_pid, contender_pid)

        for fail in (False, True):
            with self.subTest(body_raises=fail):
                expected = self.assertRaisesMessage(ValueError, 'body failed') if fail else nullcontext()
                with expected, _operation_lock(owner, 'test-operation') as check_owner:
                    # Acquisition is nonblocking, with the runner's connect and
                    # statement timeouts bounding the PostgreSQL calls.
                    with self.assertRaisesMessage(PermissionDenied, 'already being processed'):
                        with _operation_lock(contender, 'test-operation'):
                            self.fail('Contender acquired the operation lock while held')
                    with _operation_lock(connections['deletion_test'], 'test-operation'):
                        check_owner()
                    if fail:
                        raise ValueError('body failed')
                with _operation_lock(contender, 'test-operation') as check_contender:
                    check_contender()
                if owner.vendor == 'postgresql':
                    self.assertEqual(owner.connection.info.backend_pid, owner_pid)
                    self.assertEqual(contender.connection.info.backend_pid, contender_pid)

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
            with self.assertRaisesMessage(DepartmentDeletionUnavailable, 'explicitly configured'):
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
        self.assertEqual(list(AuditLog.objects.using(alias).values_list('event_type', flat=True)), [CLAIM_EVENT])
        with self.assertRaisesMessage(PermissionDenied, 'already used'):
            delete_departments(actor, [department.pk], **args)
        args['confirmation'] = prepare(actor, [department.pk], alias)[2]
        delete_departments(actor, [department.pk], **args)
        event = AuditLog.objects.using(alias).get(event_type='department.deleted')
        self.assertIsNone(event.department_id)
        self.assertFalse(Department.objects.using(alias).exists())
        self.assertFalse(AuditLog.objects.using('default').exists())


class DepartmentDeletionClaimUnitTests(SimpleTestCase):
    @override_settings(DEPARTMENT_DELETION_SESSION_AFFINITY={})
    def test_postgres_operation_lock_denies_missing_affinity_without_opening_cursor(self):
        from unittest.mock import Mock
        from .department_deletion import _operation_lock

        connection = Mock(vendor='postgresql', alias='default', settings_dict={'HOST': 'localhost'})
        with self.assertRaisesMessage(DepartmentDeletionUnavailable, 'explicitly configured backend-session affinity'):
            with _operation_lock(connection, 'operation'):
                self.fail('Unconfigured PostgreSQL session acquired the operation lock')
        connection.cursor.assert_not_called()

    def test_confirmation_response_for_missing_or_invalid_postgres_affinity(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from django.test import RequestFactory
        from . import department_deletion as service
        from .views import department_deletion_confirmation

        connection = Mock(vendor='postgresql', alias='default', settings_dict={'HOST': 'localhost'},
                          in_atomic_block=False)
        connection.get_autocommit.return_value = True
        request = RequestFactory().post('/', {
            'execute_deletion': 'yes', 'typed': 'DELETE', 'reason': 'Test unavailable',
            'confirmation': signing.dumps(
                {'actor': 1, 'using': 'default', 'ids': [2], 'operation': 'unavailable-test'}, salt=SALT),
        })
        request.user = SimpleNamespace(pk=1, is_authenticated=True, is_active=True, is_admin=True)
        for affinity in ({}, {'default': 'transaction'}):
            with (
                self.subTest(affinity=affinity),
                self.settings(DEPARTMENT_DELETION_SESSION_AFFINITY=affinity),
                patch.object(service, 'connections', {'default': connection}),
                patch.object(service.transaction, 'atomic') as atomic,
                patch.object(AuditLog.objects, 'using') as audits,
                patch.object(service, '_delete_departments') as delete,
            ):
                response = department_deletion_confirmation(request, [2])
                self.assertContains(response, 'Department deletion is currently unavailable.', status_code=503)
                connection.cursor.assert_not_called()
                atomic.assert_not_called()
                audits.assert_not_called()
                delete.assert_not_called()

    def test_claim_insert_or_commit_failure_prevents_destructive_transaction(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        from django.db import DatabaseError
        from . import department_deletion as service

        actor = SimpleNamespace(pk=1, is_authenticated=True, is_active=True, is_admin=True)
        token = signing.dumps({'actor': 1, 'using': 'default', 'ids': [2], 'operation': 'claim-test'}, salt=SALT)
        connection = MagicMock(in_atomic_block=False)
        connection.get_autocommit.return_value = True
        for stage in ('insert', 'commit'):
            claim_transaction = MagicMock()
            audits = MagicMock()
            audits.filter.return_value.exists.return_value = False
            failing_step = audits.create if stage == 'insert' else claim_transaction.__exit__
            failing_step.side_effect = DatabaseError('claim persistence failed')
            with (
                self.subTest(stage=stage),
                patch.object(service, 'connections', {'default': connection}),
                patch.object(service, '_operation_lock', return_value=nullcontext(lambda: None)),
                patch.object(service.transaction, 'atomic', return_value=claim_transaction) as atomic,
                patch.object(User.objects, 'using') as users,
                patch.object(AuditLog.objects, 'using', return_value=audits),
                patch.object(service, '_delete_departments') as delete,
            ):
                users.return_value.filter.return_value.first.return_value = actor
                with self.assertRaisesMessage(DatabaseError, 'claim persistence failed'):
                    delete_departments(actor, [2], confirmation=token, typed='DELETE', reason='Test claim')
                atomic.assert_called_once_with(using='default', durable=True)
                audits.create.assert_called_once()
                delete.assert_not_called()

    @override_settings(DEPARTMENT_DELETION_SESSION_AFFINITY={'default': 'direct'})
    def test_failure_diagnostics_report_stage_and_completed_commits(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        from django.db import OperationalError
        from . import department_deletion as service

        actor = SimpleNamespace(pk=1, is_authenticated=True, is_active=True, is_admin=True)
        token = signing.dumps({'actor': 1, 'using': 'default', 'ids': [2], 'operation': 'diagnostic'}, salt=SALT)

        class DriverFailure(Exception):
            sqlstate = '08006'

        for stage, claimed, deleted, logger_fails in (
            ('advisory_lock_acquisition', False, False, False),
            ('confirmation_claim', False, False, False),
            ('deletion_transaction', True, False, False),
            ('advisory_lock_cleanup', True, True, False),
            ('deletion_transaction', True, False, True),
        ):
            connection = MagicMock(vendor='postgresql', alias='default', in_atomic_block=False,
                                   settings_dict={'HOST': 'private-host.invalid'})
            connection.get_autocommit.return_value = True
            connection.connection.closed = False
            connection.connection.info.backend_pid = 123
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.fetchone.side_effect = [(123, True), (123,), (123, True)]
            claim = MagicMock()
            failure = OperationalError('private database error details')
            failure.__cause__ = DriverFailure('private driver details')
            with (
                self.subTest(stage=stage, logger_fails=logger_fails),
                patch.object(service, 'connections', {'default': connection}),
                patch.object(service.transaction, 'atomic', return_value=claim),
                patch.object(User.objects, 'using') as users,
                patch.object(AuditLog.objects, 'using') as audits,
                patch.object(service, '_delete_departments') as delete,
                patch.object(service.logging.getLogger('gunicorn.error'), 'error') as log,
            ):
                users.return_value.filter.return_value.first.return_value = actor
                audits.return_value.filter.return_value.exists.return_value = False
                if logger_fails:
                    log.side_effect = RuntimeError('logging unavailable')
                if stage == 'advisory_lock_acquisition':
                    cursor.execute.side_effect = failure
                elif stage == 'confirmation_claim':
                    claim.__exit__.side_effect = failure
                elif stage == 'deletion_transaction':
                    delete.side_effect = failure
                else:
                    cursor.execute.side_effect = [None, None, failure]

                with self.assertRaises(OperationalError) as caught:
                    delete_departments(actor, [2], confirmation=token, typed='DELETE', reason='Private reason')
                self.assertIs(caught.exception, failure)
                log.assert_called_once()
                self.assertEqual(log.call_args.kwargs, {})
                message, *args = log.call_args.args
                self.assertEqual(message % tuple(args),
                                 f'Department deletion failed stage={stage} exception=OperationalError '
                                 f'sqlstate=08006 claim_committed={claimed} deletion_committed={deleted}')


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

    def test_confirmation_cannot_be_replayed_when_marker_write_fails(self):
        from django.db import IntegrityError, OperationalError
        from django.db.models import QuerySet

        class LockTimeout(Exception):
            sqlstate = '55P03'

        failure = OperationalError('simulated lock timeout')
        failure.__cause__ = LockTimeout()
        original_create = QuerySet.create

        def reject_marker(query, **kwargs):
            if query.model is AuditLog and kwargs.get('event_type') == 'department.deletion_failed':
                kwargs['event_type'] = None  # Exercise the database's NOT NULL constraint.
            return original_create(query, **kwargs)

        with patch('accounts.department_deletion.record', side_effect=failure):
            with patch.object(QuerySet, 'create', reject_marker), self.assertRaises(IntegrityError):
                self.execute()
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        self.assertEqual(list(AuditLog.objects.values_list('event_type', flat=True)), [CLAIM_EVENT])
        with self.assertRaisesMessage(PermissionDenied, 'already used'):
            self.execute()
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())

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


class PostgreSQLDepartmentDeletionConcurrencyTests(TransactionTestCase):
    """Live lock regressions for the guarded disposable runner only."""

    @classmethod
    def setUpClass(cls):
        from unittest import SkipTest
        from django.conf import settings
        if settings.SETTINGS_MODULE != 'core.postgres_test_settings':
            raise SkipTest('Requires the guarded disposable PostgreSQL runner')
        from . import run_postgres_department_tests as runner
        from django.db import connection
        runner.validate_wrapper(connection)
        super().setUpClass()

    def setUp(self):
        from hashlib import sha256
        self.actor = User.objects.create_user(username='delete-admin', is_admin=True, public_key='test')
        self.department = Department.objects.create(name='Target')
        self.other = Department.objects.create(name='Unrelated')
        self.officer = User.objects.create_user(username='roster-user', department=self.department, public_key='test')
        self.membership = Membership.objects.create(user=self.officer, department=self.department)
        self.evidence = PrivateEvidenceObject.objects.create(
            key='snapshots/' + 'a' * 32 + '.png', data=b'baseline evidence',
            content_sha256=sha256(b'baseline evidence').hexdigest())
        meeting = Meeting.objects.create(department=self.department, title='Existing signed evidence')
        self.signed = Attendance.objects.create(meeting=meeting, user=self.officer)
        Attendance.objects.filter(pk=self.signed.pk).update(has_signed=True, cryptographic_signature='existing')
        self.snapshot = SigningVisualSnapshot.objects.create(
            attendance=self.signed, storage_identifier='a' * 32, content_sha256=self.evidence.content_sha256,
            byte_length=len(self.evidence.data), width=1, height=1)

    def sql(self, sql, params=None):
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchone()[0] if cursor.description else None

    def worker(self, pool, action):
        from concurrent.futures import Future
        from django.db import connections

        ready = Future()

        def run():
            try:
                self.sql("SET statement_timeout = '20s'")
                self.sql("SET lock_timeout = '12s'")
                pid = self.sql('SELECT pg_backend_pid()')
                self.assertEqual(pid, connections['default'].connection.info.backend_pid)
                ready.set_result(pid)
                return action()
            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
                raise
            finally:
                connections.close_all()

        result = pool.submit(run)
        return ready.result(timeout=10), result

    def wait(self, event):
        self.assertTrue(event.wait(10), 'Timed out waiting for transaction checkpoint')

    def blocked_by(self, waiter, blocker):
        from time import monotonic
        from threading import Event
        observer = self.sql('SELECT pg_backend_pid()')
        self.assertEqual(len({observer, waiter, blocker}), 3)
        deadline = monotonic() + 4
        poll = Event()
        while monotonic() < deadline:
            if blocker in self.sql('SELECT pg_blocking_pids(%s)', [waiter]):
                return
            poll.wait(0.02)
        self.fail(f'Backend {waiter} did not wait on {blocker}')

    def compete(self, first, second):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        paused, release = Event(), Event()

        def checkpoint():
            paused.set()
            self.wait(release)

        with ThreadPoolExecutor(max_workers=2) as pool:
            winner_pid, winner = self.worker(pool, lambda: first(checkpoint))
            try:
                self.wait(paused)
                loser_pid, loser = self.worker(pool, second)
                self.blocked_by(loser_pid, winner_pid)
            finally:
                release.set()
            winner.result(timeout=25)
            loser.result(timeout=25)
        self.fresh_session()

    def fresh_session(self):
        from django.db import connection
        previous_pid = self.sql('SELECT pg_backend_pid()')
        connection.close()
        self.assertNotEqual(self.sql('SELECT pg_backend_pid()'), previous_pid)

    def execute(self, token, ids=None):
        delete_departments(self.actor, ids or [self.department.pk], confirmation=token,
                           typed='DELETE', reason='PostgreSQL concurrency regression')

    def confirmed(self, ids=None):
        return prepare(self.actor, ids or [self.department.pk])[2]

    def pause_deletion(self, token, checkpoint, ids=None):
        from . import department_deletion as service
        original = service.inventory

        def inventory(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('lock') and self.sql('SELECT pg_backend_pid()') == owner_pid:
                checkpoint()
            return result

        owner_pid = self.sql('SELECT pg_backend_pid()')
        with patch.object(service, 'inventory', side_effect=inventory):
            self.execute(token, ids)

    def assert_preserved(self):
        from hashlib import sha256
        self.assertTrue(Department.objects.filter(pk=self.department.pk).exists())
        self.assertTrue(Membership.objects.filter(pk=self.membership.pk).exists())
        self.assertTrue(SigningVisualSnapshot.objects.filter(pk=self.snapshot.pk).exists())
        self.assertEqual(Attendance.objects.get(pk=self.signed.pk).cryptographic_signature, 'existing')
        evidence = PrivateEvidenceObject.objects.get(pk=self.evidence.pk)
        self.assertEqual(sha256(evidence.data).hexdigest(), self.evidence.content_sha256)
        self.assertFalse(AuditLog.objects.filter(event_type__in=['department.deleted', 'membership.removed']).exists())
        self.assertTrue(Department.objects.filter(pk=self.other.pk).exists())

    def assert_deleted(self):
        self.assertFalse(Department.objects.filter(pk=self.department.pk).exists())
        self.assertFalse(Meeting.objects.filter(department_id=self.department.pk).exists())
        self.assertFalse(Attendance.objects.filter(pk=self.signed.pk).exists())
        self.assertFalse(Membership.objects.filter(department_id=self.department.pk).exists())
        self.assertFalse(SigningVisualSnapshot.objects.filter(pk=self.snapshot.pk).exists())
        evidence = PrivateEvidenceObject.objects.get(pk=self.evidence.pk)
        self.assertEqual(bytes(evidence.data), bytes(self.evidence.data))
        self.assertIsNone(User.objects.get(pk=self.officer.pk).department_id)
        self.assertEqual(AuditLog.objects.filter(event_type='department.deleted').count(), 1)
        self.assertTrue(Department.objects.filter(pk=self.other.pk).exists())

    def mutation_race(self, mutate, *, deletion_first, rejection=None, message=None):
        token = self.confirmed()
        if deletion_first:
            def rejected_mutation():
                with self.assertRaisesMessage(rejection, message):
                    mutate()

            self.compete(lambda pause: self.pause_deletion(token, pause), rejected_mutation)
            self.assert_deleted()
        else:
            def held_mutation(pause):
                with transaction.atomic():
                    mutate()
                    pause()

            def rejected_deletion():
                with self.assertRaisesMessage(PermissionDenied, message or 'Affected records changed'):
                    self.execute(token)

            self.compete(held_mutation, rejected_deletion)
            self.assert_preserved()

    def assert_department_lock_precedes_meeting_lock(self, mutate):
        from django.db import connection

        locks = []

        def record_locks(execute, sql, params, many, context):
            if sql.startswith('UPDATE "accounts_department"'):
                locks.append('department')
            elif sql.startswith('UPDATE "meetings_meeting"') or (
                    'FROM "meetings_meeting"' in sql and 'FOR UPDATE' in sql):
                locks.append('meeting')
            return execute(sql, params, many, context)

        with connection.execute_wrapper(record_locks):
            mutate()
        self.assertEqual(locks[:2], ['department', 'meeting'])

    def test_overlapping_deletes_reject_the_entire_stale_selection(self):
        first = self.confirmed()
        overlap = [self.department.pk, self.other.pk]
        second = self.confirmed(overlap)
        self.assertNotEqual(signing.loads(first, salt=SALT)['operation'], signing.loads(second, salt=SALT)['operation'])

        def reject_overlap():
            with self.assertRaisesMessage(PermissionDenied, 'Department selection changed'):
                self.execute(second, overlap)

        self.compete(lambda pause: self.pause_deletion(first, pause), reject_overlap)
        self.assert_deleted()

    def test_disjoint_deletes_serialize_on_department_rows(self):
        disjoint = Department.objects.create(name='Second deletion')
        second = self.confirmed([disjoint.pk])
        first = self.confirmed()
        self.compete(lambda pause: self.pause_deletion(first, pause), lambda: self.execute(second, [disjoint.pk]))
        self.assertFalse(Department.objects.filter(pk__in=[self.department.pk, disjoint.pk]).exists())
        self.assertTrue(Department.objects.filter(pk=self.other.pk).exists())
        self.assertCountEqual(AuditLog.objects.filter(event_type='department.deleted').values_list('target_id', flat=True),
                              [str(self.department.pk), str(disjoint.pk)])
        self.assertTrue(PrivateEvidenceObject.objects.filter(pk=self.evidence.pk).exists())

    def post(self, user, data=None):
        from django.contrib.messages.storage.cookie import CookieStorage
        from django.test import RequestFactory
        request = RequestFactory().post('/', data or {})
        request.user = user
        request._messages = CookieStorage(request)
        return request

    def signing_race(self, deletion_first):
        from hashlib import sha256
        from time import time
        from .test_fixtures import complete_onboarding, finalize_meeting_fixture, signature_storage
        from meetings.crypto import generate_hmac_qr_token
        from meetings.views import sign_meeting
        from meetings.visual_evidence import read_snapshot
        signature_storage(self)
        signer = User.objects.create_user(username='concurrent-signer', first_name='Concurrent', last_name='Signer')
        complete_onboarding(signer)
        Membership.objects.create(user=signer, department=self.department)
        meeting = Meeting.objects.create(department=self.department, title='Concurrent signature')
        attendance = Attendance.objects.create(meeting=meeting, user=signer, status='Attended')
        finalize_meeting_fixture(meeting)

        def sign():
            timestamp = str(int(time()))
            request = self.post(signer, {'t': timestamp, 'sig': generate_hmac_qr_token(meeting.pk, timestamp)})
            self.assertEqual(sign_meeting(request, meeting.pk).status_code, 302)

        if deletion_first:
            self.mutation_race(sign, deletion_first=True, rejection=PermissionDenied,
                               message='attendance is read-only')
        else:
            self.mutation_race(lambda: self.assert_department_lock_precedes_meeting_lock(sign),
                               deletion_first=False)
        events = AuditLog.objects.filter(event_type='signature.created')
        if deletion_first:
            self.assertFalse(events.exists())
            self.assertFalse(SigningVisualSnapshot.objects.filter(attendance_id=attendance.pk).exists())
            self.assertTrue(User.objects.filter(pk=signer.pk).exists())
        else:
            self.assertEqual(events.count(), 1)
            attendance.refresh_from_db()
            self.assertTrue(attendance.has_signed)
            snapshot = SigningVisualSnapshot.objects.get(attendance=attendance)
            snapshot_bytes = read_snapshot(snapshot.storage_identifier, snapshot.content_sha256,
                                           snapshot.byte_length, snapshot.width, snapshot.height)
            self.assertIsNotNone(snapshot_bytes)
            with signer.signature_image.open('rb') as signature:
                self.assertEqual(sha256(snapshot_bytes).digest(), sha256(signature.read()).digest())

    def test_signing_commit_invalidates_confirmation(self):
        self.signing_race(deletion_first=False)

    def test_deletion_winner_prevents_signing(self):
        self.signing_race(deletion_first=True)

    def lifecycle_race(self, *, archive, deletion_first):
        from django.core.exceptions import ValidationError
        from django.http import Http404
        from .test_fixtures import finalize_meeting_fixture
        from meetings.views import finalize_meeting
        meeting = Meeting.objects.create(department=self.department, title='Concurrent lifecycle')
        if archive:
            finalize_meeting_fixture(meeting)

        def change_status():
            if archive:
                current = Meeting.objects.get(pk=meeting.pk)
                current.status = 'Archived'
                current.save(update_fields=['status'])
            else:
                self.assertEqual(finalize_meeting(self.post(self.actor), meeting.pk).status_code, 302)

        if archive and deletion_first:
            token = self.confirmed()

            def rejected_archive():
                with self.assertRaises(ValidationError) as caught:
                    change_status()
                error, = caught.exception.error_dict['department']
                self.assertEqual(error.code, 'invalid')
                self.assertEqual(error.params['value'], self.department.pk)

            self.compete(lambda pause: self.pause_deletion(token, pause), rejected_archive)
            self.assert_deleted()
            self.assertTrue(User.objects.filter(pk=self.actor.pk).exists())
        elif archive:
            self.mutation_race(lambda: self.assert_department_lock_precedes_meeting_lock(change_status),
                               deletion_first=False)
        else:
            self.mutation_race(change_status, deletion_first=deletion_first, rejection=Http404,
                               message='No Meeting matches' if deletion_first else None)
        events = AuditLog.objects.filter(event_type='meeting.archived' if archive else 'meeting.finalized')
        self.assertEqual(events.count(), 0 if deletion_first else 1)
        if not deletion_first:
            meeting.refresh_from_db()
            self.assertEqual(meeting.status, 'Archived' if archive else 'Finished')

    def test_finalization_commit_invalidates_confirmation(self):
        self.lifecycle_race(archive=False, deletion_first=False)

    def test_deletion_winner_prevents_finalization(self):
        self.lifecycle_race(archive=False, deletion_first=True)

    def test_archival_commit_invalidates_confirmation(self):
        self.lifecycle_race(archive=True, deletion_first=False)

    def test_deletion_winner_prevents_archival(self):
        self.lifecycle_race(archive=True, deletion_first=True)

    def membership_race(self, deletion_first):
        from .audit import grant_ap

        def promote():
            with transaction.atomic():
                grant_ap(self.actor, self.officer, self.department)

        self.mutation_race(promote, deletion_first=deletion_first, rejection=PermissionDenied,
                           message='Roster relationship scope changed' if deletion_first else None)
        self.assertEqual(AuditLog.objects.filter(event_type='user.role_changed').count(), 0 if deletion_first else 1)
        if not deletion_first:
            self.membership.refresh_from_db()
            self.assertEqual(self.membership.role, 'AP')

    def test_membership_change_invalidates_confirmation(self):
        self.membership_race(deletion_first=False)

    def test_deletion_winner_prevents_membership_change(self):
        self.membership_race(deletion_first=True)

    def reassign_race(self, deletion_first):
        retained = Membership.objects.create(user=self.officer, department=self.other)

        def reassign():
            moved = User.objects.get(pk=self.officer.pk)
            moved.department = self.other
            moved.save(update_fields=['department'])

        self.mutation_race(reassign, deletion_first=deletion_first, rejection=PermissionDenied,
                           message='Roster relationship scope changed' if deletion_first else None)
        self.officer.refresh_from_db()
        self.assertEqual(self.officer.department_id, None if deletion_first else self.other.pk)
        self.assertTrue(Membership.objects.filter(pk=retained.pk).exists())

    def test_cross_department_reassignment_invalidates_confirmation(self):
        self.reassign_race(deletion_first=False)

    def test_deletion_winner_rejects_stale_reassignment(self):
        self.reassign_race(deletion_first=True)

    def demote(self):
        User.objects.filter(pk=self.actor.pk).update(is_admin=False)

    def test_actor_demotion_wins_before_deletion_authorization_recheck(self):
        self.mutation_race(self.demote, deletion_first=False, message='Global Admin privileges changed')
        self.actor.refresh_from_db()
        self.assertFalse(self.actor.is_admin)

    def test_authorized_deletion_commits_before_waiting_actor_demotion(self):
        token = self.confirmed()
        self.compete(lambda pause: self.pause_deletion(token, pause), self.demote)
        self.assert_deleted()
        self.actor.refresh_from_db()
        self.assertFalse(self.actor.is_admin)
        with self.assertRaises(PermissionDenied):
            prepare(self.actor, [self.other.pk])

    def insert_child_with_immediate_fk(self):
        from django.db.models import QuerySet
        with transaction.atomic():
            self.sql('SET CONSTRAINTS ALL IMMEDIATE')
            # Exercise PostgreSQL's FK independently of Attendance.save()'s guard.
            QuerySet(model=Attendance, using='default').bulk_create([
                Attendance(meeting_id=self.signed.meeting_id, user_id=self.actor.pk),
            ])

    def test_child_insert_before_inventory_invalidates_confirmation(self):
        self.mutation_race(self.insert_child_with_immediate_fk, deletion_first=False)
        self.assertTrue(Attendance.objects.filter(meeting_id=self.signed.meeting_id, user=self.actor).exists())

    def test_child_insert_after_inventory_loses_to_parent_deletion(self):
        from django.db import IntegrityError
        token = self.confirmed()

        def rejected_insert():
            with self.assertRaises(IntegrityError) as caught:
                self.insert_child_with_immediate_fk()
            self.assertEqual(caught.exception.__cause__.sqlstate, '23503')

        self.compete(lambda pause: self.pause_deletion(token, pause), rejected_insert)
        self.assert_deleted()
        self.assertFalse(Attendance.objects.filter(meeting_id=self.signed.meeting_id).exists())

    def late_database_failure(self, sqlstate, *, reject_marker=False):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event, get_ident
        from django.db import IntegrityError, OperationalError, connection
        from django.db.models import QuerySet
        from .department_deletion import _operation_lock

        token = self.confirmed()
        operation = signing.loads(token, salt=SALT)['operation']
        sentinel = User.objects.create_user(username='lock-sentinel', public_key='test')
        blocker_ready, form_cycle, release_blocker = Event(), Event(), Event()
        marker_pending, publish = Event(), Event()
        observed = {}
        original_delete = QuerySet.delete
        original_create = QuerySet.create

        def lock_sentinel():
            User.objects.select_for_update().get(pk=sentinel.pk)

        def blocker():
            try:
                with transaction.atomic():
                    lock_sentinel()
                    blocker_ready.set()
                    if sqlstate == '40P01':
                        self.wait(form_cycle)
                        Department.objects.select_for_update().get(pk=self.other.pk)
                    else:
                        self.wait(release_blocker)
            except OperationalError as exc:
                observed['blocker'] = exc.__cause__.sqlstate

        def deletion():
            worker_thread = get_ident()
            pid = self.sql('SELECT pg_backend_pid()')
            raw = connection.connection

            def check_session():
                self.assertIs(connection.connection, raw)
                self.assertEqual(self.sql('SELECT pg_backend_pid()'), pid)
                self.assertEqual(raw.info.backend_pid, pid)

            def fail_after_cascade(query):
                result = original_delete(query)
                if get_ident() == worker_thread and query.model is Department:
                    self.assertFalse(Department.objects.filter(pk=self.department.pk).exists())
                    self.assertTrue(AuditLog.objects.filter(event_type='department.deleted').exists())
                    check_session()
                    try:
                        lock_sentinel()
                    except OperationalError as exc:
                        observed['deletion'] = exc.__cause__.sqlstate
                        raise
                return result

            def publish_marker(query, **kwargs):
                if (get_ident() == worker_thread and query.model is AuditLog
                        and kwargs.get('event_type') == 'department.deletion_failed'):
                    self.assertTrue(connection.get_autocommit())
                    check_session()
                    marker_pending.set()
                    self.wait(publish)
                    if reject_marker:
                        # Let PostgreSQL reject the real marker INSERT with NOT NULL.
                        kwargs['event_type'] = None
                    result = original_create(query, **kwargs)
                    check_session()
                    return result
                return original_create(query, **kwargs)

            self.sql("SET lock_timeout = '5s'" if sqlstate == '55P03' else "SET lock_timeout = '12s'")
            with patch.object(QuerySet, 'delete', fail_after_cascade), patch.object(QuerySet, 'create', publish_marker):
                expected = IntegrityError if reject_marker else PermissionDenied
                with self.assertRaises(expected) as caught:
                    self.execute(token)
                if reject_marker:
                    observed['marker'] = caught.exception.__cause__.sqlstate
                else:
                    self.assertIn('rolled back', str(caught.exception))
                check_session()

        markers = AuditLog.objects.filter(event_type='department.deletion_failed', metadata__operation_id=operation)
        with ThreadPoolExecutor(max_workers=2) as pool:
            blocker_pid, blocker_result = self.worker(pool, blocker)
            try:
                self.wait(blocker_ready)
                deletion_pid, deletion_result = self.worker(pool, deletion)
                # Start the second wait only after deletion is already waiting.
                # This gives its deadlock detector the head start. Assert the
                # actual victim below instead of treating either victim as a pass.
                self.blocked_by(deletion_pid, blocker_pid)
                form_cycle.set()
                self.wait(marker_pending)
                self.assertEqual(observed.get('deletion'), sqlstate, observed)
                self.assert_preserved()
                self.assertFalse(markers.exists())
                with self.assertRaisesMessage(PermissionDenied, 'already being processed'):
                    self.execute(token)
            finally:
                publish.set()
                form_cycle.set()
                release_blocker.set()
            deletion_result.result(timeout=25)
            blocker_result.result(timeout=25)

        self.assertNotIn('blocker', observed)
        self.fresh_session()
        self.assert_preserved()
        with _operation_lock(connection, operation) as check:
            check()
        if reject_marker:
            self.assertEqual(observed.get('marker'), '23502')
            self.assertFalse(markers.exists())
        else:
            self.assertEqual(markers.count(), 1)
        self.assertEqual(AuditLog.objects.filter(event_type=CLAIM_EVENT,
                         metadata__operation_id=operation).count(), 1)
        with self.assertRaisesMessage(PermissionDenied, 'already used'):
            self.execute(token)
        self.assert_preserved()

    def test_real_lock_timeout_rolls_back_and_consumes_confirmation(self):
        self.late_database_failure('55P03')

    def test_real_deadlock_selects_deletion_victim_and_consumes_confirmation(self):
        self.late_database_failure('40P01')

    def test_failed_marker_insert_cannot_make_confirmation_reusable(self):
        self.late_database_failure('55P03', reject_marker=True)
