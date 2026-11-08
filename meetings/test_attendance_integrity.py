from accounts.test_fixtures import set_meeting_fixture_state
from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, RequestFactory
from django.db import transaction
from django.contrib.admin.sites import AdminSite
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone
from accounts.models import User, Department, Membership
from .models import Meeting, Attendance, AuditLog, QRSession, QRUsage
from .admin import AttendanceAdmin, AttendanceAdminForm


class AttendanceIntegrityTests(TestCase):
    def setUp(self):
        from accounts.test_fixtures import signature_storage, complete_onboarding
        signature_storage(self)
        self.dept = Department.objects.create(name='Integrity')
        self.admin = User.objects.create_superuser(username='root', password='test')
        self.officer = User.objects.create_user(username='officer')
        complete_onboarding(self.officer)
        Membership.objects.create(user=self.officer, department=self.dept, role='O')
        self.meeting = Meeting.objects.create(department=self.dept, title='Record', status='Draft')
        self.archived = Meeting.objects.create(department=self.dept, title='Archive', status='Archived')
        self.att = Attendance.objects.create(meeting=self.meeting, user=self.officer)
        self.meeting.status='Finished'
        self.meeting.save()
        self.model_admin = AttendanceAdmin(Attendance, AdminSite())
        self.request = RequestFactory().post('/')
        self.request.user = self.admin

    def test_manual_finished_and_archived(self):
        self.client.force_login(self.admin)
        for name in ('meeting_attendance', 'update_attendance_status'):
            with transaction.atomic():
                args = [self.meeting.pk] + ([self.att.pk] if name == 'update_attendance_status' else [])
                url = reverse(name, args=args)
                self.assertEqual(self.client.post(url, {'attendance_id': self.att.pk, 'status': 'Late'}).status_code, 302)
                set_meeting_fixture_state(Meeting.objects.filter(pk=self.meeting.pk), status='Archived')
                before = AuditLog.objects.count()
                self.assertEqual(self.client.post(url, {'attendance_id': self.att.pk, 'status': 'Absent'}).status_code, 403)
                self.att.refresh_from_db()
                self.assertEqual(self.att.status, 'Late')
                self.assertEqual(AuditLog.objects.count(), before)
                transaction.set_rollback(True)

    def test_qr_archive_and_finished(self):
        session = QRSession.objects.create(meeting=self.meeting, purpose='attendance', token='test',
            created_by=self.admin, expires_at=timezone.now() + timedelta(hours=1))
        self.client.force_login(self.officer)
        url = reverse('scan_attendance_qr', args=[self.meeting.pk])
        with transaction.atomic():
            set_meeting_fixture_state(Meeting.objects.filter(pk=self.meeting.pk), status='Archived')
            self.assertEqual(self.client.post(url, {'token': session.token}).status_code, 403)
            self.assertFalse(QRUsage.objects.exists())
            self.assertFalse(AuditLog.objects.exists())
            transaction.set_rollback(True)
        self.assertEqual(self.client.post(url, {'token': session.token}).status_code, 200)

    def test_admin_archive_create_edit_reassign_delete(self):
        from accounts.test_fixtures import finalize_meeting_fixture
        for destination in (self.meeting, self.archived):
            obj = Attendance(meeting=destination, user=self.admin)
            with self.assertRaises(PermissionDenied), transaction.atomic():
                self.model_admin.save_model(self.request, obj, None, False)
        self.att.meeting = self.archived
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.model_admin.save_model(self.request, self.att, None, True)
        draft = Meeting.objects.create(department=self.dept, title='Archived assignment fixture')
        archived_att = Attendance.objects.create(meeting=draft, user=self.admin)
        finalize_meeting_fixture(draft, 'Archived')
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.model_admin.delete_model(self.request, archived_att)
        archived_att.meeting = self.meeting
        with self.assertRaises(PermissionDenied), transaction.atomic():
            self.model_admin.save_model(self.request, archived_att, None, True)
        self.assertFalse(AuditLog.objects.exists())

    def test_signed_fields_and_bulk_delete(self):
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=True, signed_at=timezone.now(),
            cryptographic_signature='historical', annotation='signed note')
        for field, value in (('has_signed', False), ('cryptographic_signature', 'changed'),
                             ('signed_at', None), ('annotation', 'changed'),
                             ('user_id', self.admin.pk), ('meeting_id', self.archived.pk)):
            self.att.refresh_from_db()
            setattr(self.att, field, value)
            with self.assertRaises(PermissionDenied):
                self.model_admin.save_model(self.request, self.att, None, True)
        draft = Meeting.objects.create(department=self.dept, title='Unsigned draft')
        unsigned = Attendance.objects.create(meeting=draft, user=self.admin)
        with self.assertRaises(PermissionDenied):
            self.model_admin.delete_queryset(self.request, Attendance.objects.all())
        self.assertEqual(Attendance.objects.count(), 2)
        self.att.refresh_from_db()
        with self.assertRaises(PermissionDenied):
            self.model_admin.delete_model(self.request, self.att)
        self.assertFalse(AuditLog.objects.exists())

    def test_admin_form_feedback(self):
        form = AttendanceAdminForm(data={'meeting': self.archived.pk, 'user': self.admin.pk, 'status': 'Absent'})
        self.assertFalse(form.is_valid())
        self.assertIn('read-only', str(form.errors))

    def test_qr_lifecycle_condition_at_write(self):
        from django.db.models.query import QuerySet
        original = QuerySet.update
        session = QRSession.objects.create(meeting=self.meeting, purpose='attendance', token='race',
            created_by=self.admin, expires_at=timezone.now() + timedelta(hours=1))
        def archive_before_write(queryset, **kwargs):
            if queryset.model is Attendance and kwargs.get('status') == 'Attended':
                original(Meeting.objects.filter(pk=self.meeting.pk), status='Archived')
            return original(queryset, **kwargs)
        self.client.force_login(self.officer)
        with patch.object(QuerySet, 'update', archive_before_write):
            response = self.client.post(reverse('scan_attendance_qr', args=[self.meeting.pk]), {'token': session.token})
        self.assertEqual(response.status_code, 403)
        self.att.refresh_from_db()
        self.assertEqual(self.att.status, 'Absent')
        self.assertFalse(QRUsage.objects.exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_archived_bulk_rolls_back_all(self):
        draft = Meeting.objects.create(department=self.dept, title='Archive fixture')
        Attendance.objects.create(meeting=draft, user=self.admin)
        from accounts.test_fixtures import finalize_meeting_fixture
        finalize_meeting_fixture(draft, 'Archived')
        with self.assertRaises(PermissionDenied):
            self.model_admin.delete_queryset(self.request, Attendance.objects.all())
        self.assertEqual(Attendance.objects.count(), 2)
        self.assertFalse(AuditLog.objects.exists())

    def test_signed_verification_and_qr_unchanged(self):
        from .models import VerificationQR
        from .crypto import sign_document_data, build_canonical_signing_payload, verify_attendance_signature
        payload = build_canonical_signing_payload(self.meeting.pk, self.dept.pk, self.meeting.title, '', 'note')
        signature = sign_document_data(self.officer.private_key, payload)
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=True, cryptographic_signature=signature,
                                                       annotation='note', signed_at=timezone.now())
        qr = VerificationQR.objects.create(attendance=self.att, token_hash='hash', encrypted_token='encrypted')
        self.att.refresh_from_db()
        self.att.annotation = 'tampered'
        with self.assertRaises(PermissionDenied):
            self.model_admin.save_model(self.request, self.att, None, True)
        self.att.refresh_from_db()
        result = verify_attendance_signature(self.officer.public_key, self.meeting.pk, self.dept.pk,
            self.meeting.title, '', self.att.annotation, self.att.cryptographic_signature)
        self.assertTrue(result['valid'])
        qr.refresh_from_db()
        self.assertEqual(qr.attendance_id, self.att.pk)

    def test_real_admin_signed_forgery(self):
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=True, cryptographic_signature='historical')
        self.client.force_login(self.admin)
        response = self.client.post(reverse('admin:meetings_attendance_change', args=[self.att.pk]),
                                    {'has_signed': '', 'annotation': 'tampered', '_save': 'Save'})
        self.assertEqual(response.status_code, 200)
        self.att.refresh_from_db()
        self.assertTrue(self.att.has_signed)
        self.assertNotEqual(self.att.annotation, 'tampered')
