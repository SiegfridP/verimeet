"""Focused regressions for individual and bulk administrative deletion."""
from unittest.mock import patch

from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.db import connection, connections
from django.test import RequestFactory, TestCase, TransactionTestCase

from .audit import record
from .department_deletion import delete_with_audit
from .models import Department, Membership, User
from meetings.models import Attendance, AuditLog, Meeting


class DepartmentAdminDeletionTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username='global', is_admin=True)
        self.officer = User.objects.create_user(username='officer')
        self.ap = User.objects.create_user(username='ap', is_staff=True)
        self.first = Department.objects.create(name='First')
        self.second = Department.objects.create(name='Second')
        Membership.objects.create(user=self.officer, department=self.first)
        Membership.objects.create(user=self.ap, department=self.second, role='AP')
        self.request = RequestFactory().post('/admin/')
        self.request.user = self.actor
        self.model_admin = admin.site._registry[Department]

    def test_individual_and_bulk_require_global_authority_even_empty(self):
        for actor in (self.ap, self.officer):
            self.request.user = actor
            self.assertFalse(self.model_admin.has_delete_permission(self.request))
            for operation in (
                lambda: self.model_admin.delete_model(self.request, self.first),
                lambda: self.model_admin.delete_queryset(self.request, Department.objects.all()),
                lambda: self.model_admin.delete_queryset(self.request, Department.objects.none()),
            ):
                with self.assertRaises(PermissionDenied):
                    operation()
        self.assertEqual(Department.objects.count(), 2)
        self.assertFalse(AuditLog.objects.exists())

    def test_successful_bulk_has_exactly_one_event_per_target(self):
        expected_memberships = set(map(str, Membership.objects.values_list('pk', flat=True)))
        expected_departments = {str(self.first.pk), str(self.second.pk)}
        self.model_admin.delete_queryset(self.request, Department.objects.order_by('-pk'))
        self.assertFalse(Department.objects.exists())
        self.assertFalse(Membership.objects.exists())
        removed = AuditLog.objects.filter(event_type='membership.removed')
        deleted = AuditLog.objects.filter(event_type='department.deleted')
        self.assertEqual(removed.count(), 2)
        self.assertEqual(deleted.count(), 2)
        self.assertEqual(set(removed.values_list('target_id', flat=True)), expected_memberships)
        self.assertEqual(set(deleted.values_list('target_id', flat=True)), expected_departments)
        self.assertEqual(AuditLog.objects.filter(user=self.actor, department__isnull=True).count(), 4)

    def test_later_protected_department_rolls_back_earlier_delete_and_audits(self):
        Meeting.objects.create(department=self.second, title='Protected', status='Finished')
        with self.assertRaises(PermissionDenied):
            self.model_admin.delete_queryset(self.request, Department.objects.order_by('pk'))
        self.assertEqual(Department.objects.count(), 2)
        self.assertEqual(Membership.objects.count(), 2)
        self.assertTrue(Meeting.objects.filter(department=self.second).exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_audit_failure_rolls_back_entire_bulk(self):
        def fail_second(actor, event_type, target, *args, **kwargs):
            if event_type == 'department.deleted' and target.pk == self.second.pk:
                raise RuntimeError('Audit unavailable')
            return record(actor, event_type, target, *args, **kwargs)

        with patch('accounts.department_deletion.record', side_effect=fail_second):
            with self.assertRaises(RuntimeError):
                self.model_admin.delete_queryset(self.request, Department.objects.all())
        self.assertEqual(Department.objects.count(), 2)
        self.assertEqual(Membership.objects.count(), 2)
        self.assertFalse(AuditLog.objects.exists())

    def test_helper_passes_database_alias_to_audit_and_delete(self):
        with patch('accounts.department_deletion.record', wraps=record) as events:
            with patch.object(self.first, 'delete', wraps=self.first.delete) as delete:
                delete_with_audit(self.actor, self.first)
        delete.assert_called_once_with(using='default')
        self.assertEqual(len(events.call_args_list), 2)
        for call in events.call_args_list:
            self.assertEqual(call.kwargs['using'], 'default')

    def test_bulk_locks_all_departments_before_meeting_and_attendance(self):
        for department in (self.first, self.second):
            meeting = Meeting.objects.create(department=department, title='Safe')
            Attendance.objects.create(meeting=meeting, user=self.officer)
        writes = []

        def trace(execute, sql, params, many, context):
            if sql.lstrip().upper().startswith('UPDATE "ACCOUNTS_DEPARTMENT"'):
                writes.append(('department', params[-1]))
            if sql.lstrip().upper().startswith('UPDATE "MEETINGS_MEETING"'):
                writes.append(('meeting', params[-1]))
            return execute(sql, params, many, context)

        with connection.execute_wrapper(trace):
            self.model_admin.delete_queryset(self.request, Department.objects.order_by('-pk'))
        self.assertEqual(writes[:2], [('department', self.first.pk), ('department', self.second.pk)])
        self.assertTrue(any(kind == 'meeting' for kind, _ in writes))


class DepartmentDeletionDatabaseTests(TransactionTestCase):
    databases = '__all__'

    def test_deletion_keeps_records_and_transaction_on_selected_database(self):
        # Also exercised with an independent second SQLite database by the
        # focused multi-database runner; normal project settings have one alias.
        for using in connections:
            with self.subTest(using=using):
                actor = User.objects.db_manager(using).create_user(
                    username='alias-admin', is_admin=True, public_key='test-public-key')
                safe = Department.objects.using(using).create(name='Alias safe')
                protected = Department.objects.using(using).create(name='Alias protected')
                Membership.objects.using(using).create(user=actor, department=safe)
                Meeting.objects.using(using).create(department=protected, title='Evidence', status='Finished')
                request = RequestFactory().post('/admin/'); request.user = actor
                model_admin = admin.site._registry[Department]
                with self.assertRaises(PermissionDenied):
                    model_admin.delete_queryset(request, Department.objects.using(using).order_by('pk'))
                self.assertEqual(Department.objects.using(using).count(), 2)
                self.assertFalse(AuditLog.objects.using(using).exists())
                delete_with_audit(actor, safe)
                self.assertFalse(Department.objects.using(using).filter(pk=safe.pk).exists())
                self.assertEqual(AuditLog.objects.using(using).filter(event_type='department.deleted').count(), 1)
                self.assertEqual(AuditLog.objects.using(using).filter(event_type='membership.removed').count(), 1)
