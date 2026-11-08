from django.test import TestCase, RequestFactory
from django.contrib.admin.sites import AdminSite
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.db import transaction
from django.utils import timezone
from accounts.models import User, Department, Membership
from accounts.admin import DepartmentAdmin, CustomUserAdmin
from .models import Meeting, Attendance, VerificationQR, AuditLog
from .admin import MeetingAdmin, AttendanceAdmin


class ParentDeletionTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username='root', password='test')
        self.department = Department.objects.create(name='Protected')
        self.user = User.objects.create_user(username='signer')
        Membership.objects.create(user=self.user, department=self.department, role='O')
        self.meeting = Meeting.objects.create(department=self.department, title='Evidence', status='Finished')
        self.att = Attendance.objects.create(meeting=self.meeting, user=self.user,
            has_signed=True, cryptographic_signature='historical', signed_at=timezone.now(), annotation='Evidence')
        self.qr = VerificationQR.objects.create(attendance=self.att, token_hash='hash', encrypted_token='encrypted')
        self.request = RequestFactory().post('/')
        self.request.user = self.admin

    def assert_evidence(self):
        for obj in (self.department, self.user, self.meeting, self.att, self.qr):
            self.assertTrue(type(obj).objects.filter(pk=obj.pk).exists())
        self.att.refresh_from_db()
        self.assertEqual(self.att.cryptographic_signature, 'historical')
        self.assertFalse(AuditLog.objects.exists())

    def test_signed_orm_instance_and_queryset_deletions(self):
        for obj in (self.att, self.meeting, self.user, self.department):
            with self.subTest(model=type(obj).__name__, path='instance'):
                with self.assertRaises(PermissionDenied), transaction.atomic():
                    obj.delete()
                self.assert_evidence()
            with self.subTest(model=type(obj).__name__, path='queryset'):
                with self.assertRaises(PermissionDenied), transaction.atomic():
                    type(obj).objects.filter(pk=obj.pk).delete()
                self.assert_evidence()

    def test_archived_unsigned_parent_deletions(self):
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=False, cryptographic_signature='', signed_at=None)
        Meeting.objects.filter(pk=self.meeting.pk).update(status='Archived')
        for obj in (self.att, self.meeting, self.user, self.department):
            with self.subTest(model=type(obj).__name__):
                with self.assertRaises(PermissionDenied), transaction.atomic():
                    type(obj).objects.filter(pk=obj.pk).delete()
                self.assertTrue(type(obj).objects.filter(pk=obj.pk).exists())
                self.assertTrue(VerificationQR.objects.filter(pk=self.qr.pk).exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_admin_hooks_rollback_audit_and_mixed_bulk(self):
        site = AdminSite()
        for model, klass, protected in ((Meeting, MeetingAdmin, self.meeting),
                (User, CustomUserAdmin, self.user), (Department, DepartmentAdmin, self.department)):
            admin = klass(model, site)
            if model is Meeting:
                safe = Meeting.objects.create(department=self.department, title='Safe')
            elif model is User:
                safe = User.objects.create_user(username='safe')
            else:
                safe = Department.objects.create(name='Safe')
            with self.subTest(model=model.__name__, path='individual'):
                with self.assertRaises(PermissionDenied), transaction.atomic():
                    admin.delete_model(self.request, protected)
                self.assert_evidence()
            with self.subTest(model=model.__name__, path='bulk'):
                with self.assertRaises(PermissionDenied), transaction.atomic():
                    admin.delete_queryset(self.request, model.objects.filter(pk__in=[safe.pk, protected.pk]))
                self.assertTrue(model.objects.filter(pk=safe.pk).exists())
                self.assert_evidence()

    def test_real_admin_parent_posts_preserve_evidence(self):
        self.client.force_login(self.admin)
        for app, model, obj in (('meetings', 'meeting', self.meeting),
                               ('accounts', 'user', self.user), ('accounts', 'department', self.department)):
            response = self.client.post(reverse(f'admin:{app}_{model}_delete', args=[obj.pk]), {'post': 'yes'})
            self.assertIn(response.status_code, (200, 403))
            self.assertContains(response, 'Cannot delete' if response.status_code == 200 else '403 Forbidden',
                                status_code=response.status_code)
            self.assert_evidence()
            response = self.client.post(reverse(f'admin:{app}_{model}_changelist'),
                {'action': 'delete_selected', '_selected_action': [obj.pk], 'post': 'yes'})
            self.assertIn(response.status_code, (200, 403))
            self.assertContains(response, 'Cannot delete' if response.status_code == 200 else '403 Forbidden',
                                status_code=response.status_code)
            self.assert_evidence()

    def test_unsigned_records_keep_normal_deletion_policy(self):
        # Isolate each cascade so each parent still exists when tested.
        for parent in ('attendance', 'meeting', 'user', 'department'):
            dept = Department.objects.create(name=f'Safe {parent}')
            user = User.objects.create_user(username=f'safe_{parent}')
            # Department deletion now protects Finished meetings even unsigned.
            meeting = Meeting.objects.create(department=dept, title='Safe', status='Draft' if parent == 'department' else 'Finished')
            attendance = Attendance.objects.create(meeting=meeting, user=user)
            target = {'attendance': attendance, 'meeting': meeting, 'user': user, 'department': dept}[parent]
            target.delete()
            self.assertFalse(Attendance.objects.filter(pk=attendance.pk).exists())

    def test_signature_alone_is_protected(self):
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=False, signed_at=None)
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.meeting.delete()
        self.assert_evidence()

    def test_guard_locks_meeting_before_attendance(self):
        from django.db import connection
        from django.db.models.query import QuerySet
        from unittest.mock import patch
        from .deletion_guards import protect_attendance_evidence
        events = []
        original = QuerySet.select_for_update
        def lock(queryset, *args, **kwargs):
            if queryset.model is Attendance:
                events.append('attendance_lock')
            return original(queryset, *args, **kwargs)
        def execute(execute, sql, params, many, context):
            if sql.lstrip().upper().startswith('UPDATE "MEETINGS_MEETING"'):
                events.append('meeting_write')
            return execute(sql, params, many, context)
        # Invoke the actual receiver and execute real queries. SQLite cannot prove
        # PostgreSQL contention safety; this checks the receiver's lock ordering.
        with patch.object(QuerySet, 'select_for_update', lock), connection.execute_wrapper(execute):
            with self.assertRaises(PermissionDenied), transaction.atomic():
                protect_attendance_evidence(Attendance, self.att, connection.alias)
        self.assertEqual(events, ['meeting_write', 'attendance_lock'])
        self.assert_evidence()

    def test_stale_collector_instance_uses_persisted_meeting(self):
        safe = Meeting.objects.create(department=self.department, title='Stale collector')
        self.att.meeting = safe
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.att.delete()
        self.assert_evidence()

    def test_attendance_admin_lock_order(self):
        from django.db import connection
        from django.db.models.query import QuerySet
        from unittest.mock import patch
        admin = AttendanceAdmin(Attendance, AdminSite())
        other = Meeting.objects.create(department=self.department, title='Other')
        for operation in ('save', 'delete', 'bulk'):
            with self.subTest(operation=operation):
                with transaction.atomic():
                    # Roll back each successful operation to reuse the same records.
                    Attendance.objects.filter(pk=self.att.pk).update(has_signed=False, cryptographic_signature='', signed_at=None)
                    self.att.refresh_from_db()
                    extra = Attendance.objects.create(meeting=other, user=self.user)
                    events = []
                    original = QuerySet.select_for_update
                    def lock(queryset, *args, **kwargs):
                        if queryset.model is Attendance:
                            events.append(('attendance', None))
                        return original(queryset, *args, **kwargs)
                    def execute(execute, sql, params, many, context):
                        if sql.lstrip().upper().startswith('UPDATE "MEETINGS_MEETING"'):
                            events.append(('meeting', params[0]))
                        return execute(sql, params, many, context)
                    with patch.object(QuerySet, 'select_for_update', lock), connection.execute_wrapper(execute):
                        if operation == 'save':
                            self.att.status = 'Late'
                            admin.save_model(self.request, self.att, None, True)
                        elif operation == 'delete':
                            admin.delete_model(self.request, self.att)
                        else:
                            admin.delete_queryset(self.request, Attendance.objects.order_by('-meeting_id'))
                    first_attendance = next(i for i, event in enumerate(events) if event[0] == 'attendance')
                    meetings = [event[1] for event in events[:first_attendance]]
                    self.assertEqual(meetings, sorted([self.meeting.pk, other.pk]) if operation == 'bulk' else [self.meeting.pk])
                    expected = 2 if operation == 'bulk' else 1
                    self.assertEqual(AuditLog.objects.filter(event_type='attendance.changed' if operation == 'save' else 'attendance.deleted').count(), expected)
                    transaction.set_rollback(True)

    def test_attendance_admin_protected_deletions(self):
        admin = AttendanceAdmin(Attendance, AdminSite())
        for archived in (False, True):
            with self.subTest(archived=archived), transaction.atomic():
                if archived:
                    Attendance.objects.filter(pk=self.att.pk).update(has_signed=False, cryptographic_signature='', signed_at=None)
                    Meeting.objects.filter(pk=self.meeting.pk).update(status='Archived')
                safe_meeting = Meeting.objects.create(department=self.department, title='Unprotected')
                safe = Attendance.objects.create(meeting=safe_meeting, user=self.user)
                for bulk in (False, True):
                    with self.assertRaises(PermissionDenied), transaction.atomic():
                        if bulk:
                            admin.delete_queryset(self.request, Attendance.objects.all())
                        else:
                            admin.delete_model(self.request, self.att)
                    self.assertTrue(Attendance.objects.filter(pk=safe.pk).exists())
                    self.assertTrue(Attendance.objects.filter(pk=self.att.pk).exists())
                    self.assertTrue(VerificationQR.objects.filter(pk=self.qr.pk).exists())
                    self.assertFalse(AuditLog.objects.exists())
                transaction.set_rollback(True)

    def test_admin_reassignment_race_fails_closed(self):
        from unittest.mock import patch
        from .attendance_integrity import lock_mutable_meetings
        admin = AttendanceAdmin(Attendance, AdminSite())
        destination = Meeting.objects.create(department=self.department, title='Changed association')
        def reassign_after_meeting_lock(ids):
            lock_mutable_meetings(ids)
            Attendance.objects.filter(pk=self.att.pk).update(meeting=destination)
        for operation in ('save', 'delete', 'bulk'):
            self.att.refresh_from_db()
            with self.subTest(operation=operation):
                with patch('meetings.admin.lock_mutable_meetings', side_effect=reassign_after_meeting_lock) as guard:
                    with self.assertRaisesMessage(PermissionDenied, 'Attendance changed'):
                        if operation == 'save':
                            admin.save_model(self.request, self.att, None, True)
                        elif operation == 'delete':
                            admin.delete_model(self.request, self.att)
                        else:
                            admin.delete_queryset(self.request, Attendance.objects.all())
                    self.assertEqual(guard.call_count, 1)
                self.assert_evidence()
