from hashlib import sha256
import time
from unittest.mock import patch
from django.test import TestCase
from django.test import TransactionTestCase
from django.urls import reverse
from django.db import transaction
from django.core.exceptions import PermissionDenied
from accounts.models import User, Department, Membership
from accounts.test_fixtures import signature_storage, complete_onboarding
from accounts.test_onboarding import png
from accounts.signature_replacement import replace_signature, version
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import Meeting, Attendance, SigningVisualSnapshot, AuditLog, QRUsage
from .crypto import generate_hmac_qr_token
from .pdf import capture_document, generate_meeting_pdf
from .visual_evidence import SnapshotStorage, read_snapshot


class VisualEvidenceTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.user = User.objects.create_user(username='private', first_name='Original', last_name='Signer')
        complete_onboarding(self.user)
        self.dept = Department.objects.create(name='Evidence')
        Membership.objects.create(user=self.user, department=self.dept)
        self.meeting = Meeting.objects.create(department=self.dept, title='Final', status='Finished')
        self.att = Attendance.objects.create(meeting=self.meeting, user=self.user, status='Attended')
        self.client.force_login(self.user)

    def sign(self, meeting=None):
        meeting = meeting or self.meeting
        timestamp = str(int(time.time()))
        return self.client.post(reverse('sign_meeting', args=[meeting.pk]), {
            't': timestamp, 'sig': generate_hmac_qr_token(meeting.pk, timestamp), 'annotation': 'Approved'})

    def test_capture_exact_bytes_name_and_crypto(self):
        with self.user.signature_image.open('rb') as stream:
            original = stream.read()
        self.assertEqual(self.sign().status_code, 302)
        snapshot = SigningVisualSnapshot.objects.get(attendance=self.att)
        self.assertEqual(snapshot.content_sha256, sha256(original).hexdigest())
        self.assertEqual(read_snapshot(snapshot.storage_identifier, snapshot.content_sha256,
            snapshot.byte_length, snapshot.width, snapshot.height), original)
        document = capture_document(self.meeting.pk)
        self.assertEqual(document['attendees'][0]['name'], 'Original Signer')
        self.assertEqual(document['attendees'][0]['verification'], 'Valid canonical ECDSA signature')
        self.assertEqual(list(document['resources'].values()), [original])
        self.assertEqual(self.sign().status_code, 403)
        self.assertEqual(SigningVisualSnapshot.objects.count(), 1)

    def test_replacement_and_renaming_preserve_history(self):
        self.sign()
        old = list(capture_document(self.meeting.pk)['resources'].values())[0]
        self.user.refresh_from_db()
        replace_signature(self.user, SimpleUploadedFile('b.png', png(color=(255, 0, 0, 255))), version(self.user))
        User.objects.filter(pk=self.user.pk).update(first_name='New')
        second = Meeting.objects.create(department=self.dept, title='Second', status='Finished')
        Attendance.objects.create(meeting=second, user=self.user, status='Late')
        self.assertEqual(self.sign(second).status_code, 302)
        self.meeting.status = 'Archived'; self.meeting.save()
        first_document = capture_document(self.meeting.pk)
        self.assertEqual(first_document['attendees'][0]['name'], 'Original Signer')
        self.assertEqual(list(first_document['resources'].values()), [old])
        self.assertNotEqual(list(capture_document(second.pk)['resources'].values()), [old])

    def test_storage_failure_rolls_back(self):
        with patch.object(SnapshotStorage, 'save', side_effect=OSError('private path')):
            response = self.sign()
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, 'private path', status_code=400)
        self.att.refresh_from_db(); self.assertFalse(self.att.has_signed)
        self.assertFalse(SigningVisualSnapshot.objects.exists())
        self.assertFalse(QRUsage.objects.exists())
        self.assertFalse(AuditLog.objects.filter(event_type='signature.created').exists())

    def test_readback_failure_rolls_back(self):
        with patch('meetings.visual_evidence.read_snapshot', return_value=None):
            self.assertEqual(self.sign().status_code, 400)
        self.att.refresh_from_db(); self.assertFalse(self.att.has_signed)
        self.assertFalse(SigningVisualSnapshot.objects.exists())

    def test_audit_failure_rolls_back_snapshot(self):
        with patch('meetings.views.AuditLog.objects.create', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError): self.sign()
        self.assertFalse(SigningVisualSnapshot.objects.exists())
        self.att.refresh_from_db(); self.assertFalse(self.att.has_signed)

    def test_missing_corrupt_and_invalid_are_independent(self):
        self.sign()
        snapshot = SigningVisualSnapshot.objects.get()
        Attendance.objects.filter(pk=self.att.pk).update(cryptographic_signature='invalid')
        document = capture_document(self.meeting.pk)
        self.assertEqual(document['attendees'][0]['verification'], 'Invalid signature')
        self.assertTrue(document['resources'])
        with SnapshotStorage().open(snapshot.storage_identifier, 'wb') as stream:
            stream.write(b'corrupt')  # Simulated external storage damage, not an application API.
        document = capture_document(self.meeting.pk)
        self.assertFalse(document['resources'])
        self.assertEqual(document['attendees'][0]['verification'], 'Invalid signature')
        self.assertTrue(generate_meeting_pdf(document).startswith(b'%PDF'))


class VisualConcurrencyTests(TransactionTestCase):
    setUp = VisualEvidenceTests.setUp
    sign = VisualEvidenceTests.sign

    def test_replacement_waiting_on_signing_never_changes_captured_bytes(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from django.db import connections, OperationalError
        from .visual_evidence import capture
        locked = Event()
        attempted = Event()
        with self.user.signature_image.open('rb') as stream:
            original = stream.read()
        def capturing(attendance, user):
            locked.set()
            self.assertTrue(attempted.wait(10))
            return capture(attendance, user)
        def replacement():
            try:
                self.assertTrue(locked.wait(10))
                attempted.set()
                try:
                    user = User.objects.get(pk=self.user.pk)
                    token = version(user)
                    replace_signature(user, SimpleUploadedFile('new.png', png(color=(255, 0, 0, 255))), token)
                except OperationalError:
                    pass  # SQLite may reject contention; retry remains a separate request.
            finally:
                attempted.set()
                connections.close_all()
        with ThreadPoolExecutor(max_workers=1) as pool:
            worker = pool.submit(replacement)
            with patch('meetings.visual_evidence.capture', side_effect=capturing):
                self.assertEqual(self.sign().status_code, 302)
            worker.result(timeout=20)
        self.assertEqual(list(capture_document(self.meeting.pk)['resources'].values()), [original])

    def test_immutability_and_parent_deletion(self):
        self.sign()
        snapshot = SigningVisualSnapshot.objects.get()
        snapshot.signer_name = 'Changed'
        with self.assertRaises(PermissionDenied): snapshot.save()
        with self.assertRaises(PermissionDenied): SigningVisualSnapshot.objects.update(signer_name='Changed')
        from django.db.models.deletion import ProtectedError
        for obj in (snapshot, self.att, self.meeting, self.user, self.dept):
            with self.subTest(model=type(obj).__name__), self.assertRaises((PermissionDenied, ProtectedError)), transaction.atomic():
                obj.delete()
        self.assertTrue(SigningVisualSnapshot.objects.exists())
        with self.assertRaises(PermissionDenied): SnapshotStorage().url(snapshot.storage_identifier)

    def test_legacy_never_uses_profile(self):
        Attendance.objects.filter(pk=self.att.pk).update(has_signed=True, cryptographic_signature='historical')
        attendee = capture_document(self.meeting.pk)['attendees'][0]
        self.assertEqual(attendee['name'], 'Name unavailable')
        self.assertIsNone(attendee['image_url'])

    def test_admin_without_png_cannot_sign(self):
        admin = User.objects.create_user(username='admin', is_admin=True)
        Attendance.objects.create(meeting=self.meeting, user=admin, status='Attended')
        self.client.force_login(admin)
        self.assertEqual(self.sign().status_code, 400)
        self.assertFalse(SigningVisualSnapshot.objects.exists())

    def test_deactivation_after_meeting_guard_is_rechecked(self):
        from accounts.account_status import change_account_status
        from .attendance_integrity import lock_mutable_meetings
        admin = User.objects.create_user(username='controller', is_admin=True)
        def deactivate(ids):
            lock_mutable_meetings(ids)
            change_account_status(admin, self.user.pk, False)
        with patch('meetings.views.lock_mutable_meetings', side_effect=deactivate):
            self.assertEqual(self.sign().status_code, 403)
        self.assertFalse(SigningVisualSnapshot.objects.exists())

    def test_hash_length_dimensions_and_missing_fail_closed(self):
        self.sign()
        snapshot = SigningVisualSnapshot.objects.get()
        args = [snapshot.storage_identifier, snapshot.content_sha256, snapshot.byte_length,
                snapshot.width, snapshot.height]
        for index, value in ((0, '0' * 32 + '.png'), (1, '0' * 64), (2, 1), (3, 1), (4, 1)):
            modified = args.copy(); modified[index] = value
            self.assertIsNone(read_snapshot(*modified))
        with patch('meetings.pdf.MAX_IMAGE_PIXELS', 1):
            document = capture_document(self.meeting.pk)
        self.assertFalse(document['resources'])
        self.assertEqual(document['attendees'][0]['verification'], 'Valid canonical ECDSA signature')

    def test_reassignment_bulk_and_storage_deletion_rejected(self):
        self.sign()
        snapshot = SigningVisualSnapshot.objects.get()
        with self.assertRaises(PermissionDenied):
            SigningVisualSnapshot.objects.bulk_update([snapshot], ['signer_name'])
        with self.assertRaises(PermissionDenied):
            SigningVisualSnapshot.objects.all().delete()
        with self.assertRaises(PermissionDenied):
            SnapshotStorage().delete(snapshot.storage_identifier)
        from django.db import IntegrityError
        impostor = SigningVisualSnapshot(pk=snapshot.pk, attendance=self.att,
            storage_identifier='0' * 32 + '.png', content_sha256='0' * 64,
            byte_length=1, width=1, height=1, signer_name='Forged')
        with patch('meetings.models.SigningVisualSnapshot.objects.filter') as query:
            query.return_value.exists.return_value = False  # Concurrent insertion after the existence check.
            with self.assertRaises(IntegrityError), transaction.atomic():
                impostor.save()
        snapshot.refresh_from_db()
        self.assertEqual(snapshot.signer_name, 'Original Signer')

    def test_empty_name_is_neutral_and_frozen(self):
        User.objects.filter(pk=self.user.pk).update(first_name='', last_name='')
        self.sign()
        User.objects.filter(pk=self.user.pk).update(first_name='Later')
        self.assertEqual(capture_document(self.meeting.pk)['attendees'][0]['name'], 'Name unavailable')

    def test_real_renderer_uses_only_export_bytes(self):
        self.sign()
        document = capture_document(self.meeting.pk)
        from weasyprint import HTML
        from django.template.loader import render_to_string
        html = render_to_string('pdf/final_minutes.html', {'document': document})
        metadata = HTML(string=html).render().metadata
        self.assertEqual(metadata.title, 'Final')
        self.assertEqual(metadata.generator, 'VeriMeet')
        self.assertNotIn('private', html)
        self.assertNotIn('token=', html)
        seen = []
        class RecordingResources(dict):
            def __getitem__(self, key):
                seen.append(key)
                return super().__getitem__(key)
        document['resources'] = RecordingResources(document['resources'])
        self.assertTrue(generate_meeting_pdf(document).startswith(b'%PDF'))
        self.assertEqual(seen, [document['attendees'][0]['image_url']])

    def test_database_insert_failure_rolls_back_signed_state(self):
        with patch('meetings.models.SigningVisualSnapshot.objects.create', side_effect=RuntimeError):
            self.assertEqual(self.sign().status_code, 400)
        self.att.refresh_from_db()
        self.assertFalse(self.att.has_signed)
        self.assertFalse(self.att.cryptographic_signature)
        self.assertFalse(QRUsage.objects.exists())
        self.assertFalse(AuditLog.objects.filter(event_type='signature.created').exists())

    def test_multiple_officers_and_status_cycles_preserve_images(self):
        from accounts.account_status import change_account_status
        self.sign()
        other = User.objects.create_user(username='second', first_name='Second')
        complete_onboarding(other)
        Membership.objects.create(user=other, department=self.dept)
        Attendance.objects.create(meeting=self.meeting, user=other, status='Late')
        self.client.force_login(other)
        self.assertEqual(self.sign().status_code, 302)
        admin = User.objects.create_user(username='controller', is_admin=True)
        change_account_status(admin, self.user.pk, False)
        change_account_status(admin, self.user.pk, True)
        document = capture_document(self.meeting.pk)
        self.assertEqual([a['name'] for a in document['attendees']], ['Original Signer', 'Second'])
        self.assertEqual(len(document['resources']), 2)

    def test_revocation_after_meeting_lock_prevents_capture(self):
        from datetime import timedelta
        from django.utils import timezone
        from .models import QRSession
        from .attendance_integrity import lock_mutable_meetings
        session = QRSession.objects.create(meeting=self.meeting, created_by=self.user,
            purpose='signing', token='signing-token', expires_at=timezone.now()+timedelta(hours=1))
        def revoke(ids):
            lock_mutable_meetings(ids)
            QRSession.objects.filter(pk=session.pk).update(is_revoked=True)
        with patch('meetings.views.lock_mutable_meetings', side_effect=revoke):
            response = self.client.post(reverse('sign_meeting', args=[self.meeting.pk]), {'token': session.token})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(SigningVisualSnapshot.objects.exists())
        self.assertFalse(QRUsage.objects.exists())
