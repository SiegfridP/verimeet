from unittest.mock import patch
from django.test import TestCase, TransactionTestCase, Client
from django.urls import reverse
from django.core.exceptions import PermissionDenied
from django.contrib import admin
from django.test import RequestFactory
from django.db import transaction
from django.utils import timezone
from .models import Department, Membership, User, RoleElevationRequest, Invitation, InvitationDelivery
from meetings.models import Meeting, Attendance, VerificationQR, AuditLog


class Batch14Tests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='creator')
        self.admin = User.objects.create_user(username='global', is_admin=True)
        self.dept = Department.objects.create(name='Private', contact_email='private@example.com')
        self.client.force_login(self.user)

    def test_creation_and_existing_membership(self):
        old = Membership.objects.create(user=self.user, department=self.dept)
        response = self.client.post(reverse('create_department'), {'name': 'New', 'contact_email': 'new@example.com'})
        new = Department.objects.get(name='New')
        self.assertTrue(new.is_active)
        self.assertEqual(Membership.objects.get(user=self.user, department=new).role, 'AP')
        self.assertTrue(Membership.objects.filter(pk=old.pk).exists())
        self.assertRedirects(response, reverse('department_dashboard', args=[new.pk]))
        self.user.refresh_from_db()
        self.assertIsNone(self.user.department_id)

    def test_creation_rollback(self):
        with patch('accounts.views.Membership.objects.create', side_effect=RuntimeError):
            response = self.client.post(reverse('create_department'), {'name': 'Failed', 'contact_email': 'x@example.com'})
        self.assertContains(response, 'could not be created')
        self.assertFalse(Department.objects.filter(name='Failed').exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_creation_audit_failure_rolls_back(self):
        with patch('accounts.views.record', side_effect=RuntimeError):
            self.client.post(reverse('create_department'), {'name': 'Failed audit', 'contact_email': 'x@example.com'})
        self.assertFalse(Department.objects.filter(name='Failed audit').exists())
        self.assertFalse(Membership.objects.filter(user=self.user).exists())

    def test_creation_auth_csrf_duplicate(self):
        self.client.logout()
        self.assertEqual(self.client.post(reverse('create_department')).status_code, 302)
        client = Client(enforce_csrf_checks=True); client.force_login(self.user)
        self.assertEqual(client.post(reverse('create_department')).status_code, 403)
        self.client.force_login(self.user)
        response = self.client.post(reverse('create_department'), {'name': 'Private', 'contact_email': 'x@example.com'})
        self.assertContains(response, 'This name is unavailable')
        self.assertNotContains(response, 'private@example.com')

    def test_waiting_and_pending_invitation(self):
        response = self.client.get(reverse('waiting_room'))
        self.assertContains(response, 'Create Department'); self.assertContains(response, 'Accept Invitation')
        self.assertNotContains(response, self.dept.name)
        invite = Invitation.objects.create(email='x@example.com', department=self.dept, inviter=self.admin)
        session = self.client.session; session['pending_invite_token'] = invite.token; session.save()
        self.assertContains(self.client.get(reverse('waiting_room')), reverse('accept_invitation', args=[invite.token]))

    def test_private_endpoints(self):
        for name in ('department_dashboard', 'invite_member', 'request_authorized_personnel'):
            for pk in (self.dept.pk, 999999):
                self.assertEqual(self.client.get(reverse(name, args=[pk])).status_code, 404)

    def test_legacy_save_does_not_join(self):
        self.user.department = self.dept; self.user.save()
        self.assertFalse(Membership.objects.filter(user=self.user).exists())

    def test_elevation_requires_current_membership(self):
        Membership.objects.create(user=self.admin, department=self.dept, role='AP')
        self.client.force_login(self.admin)
        self.user.email = 'target@example.com'; self.user.save()
        url = reverse('request_authorized_personnel', args=[self.dept.pk])
        self.assertEqual(self.client.post(url, {'target_email': self.user.email}).status_code, 400)
        membership = Membership.objects.create(user=self.user, department=self.dept)
        self.assertEqual(self.client.post(url, {'target_email': self.user.email}).status_code, 302)
        req = RoleElevationRequest.objects.get()
        for endpoint in ('admin_dashboard', 'review_elevation_requests'):
            Department.objects.filter(pk=self.dept.pk).update(is_active=False)
            self.assertEqual(self.client.post(reverse(endpoint), {'request_id': req.pk, 'action': 'approve'}).status_code, 400)
            Department.objects.filter(pk=self.dept.pk).update(is_active=True)
        membership.delete()
        self.assertEqual(self.client.post(reverse('review_elevation_requests'), {'request_id': req.pk, 'action': 'approve'}).status_code, 400)
        membership = Membership.objects.create(user=self.user, department=self.dept)
        self.assertEqual(self.client.post(reverse('review_elevation_requests'), {'request_id': req.pk, 'action': 'approve'}).status_code, 302)
        membership.refresh_from_db(); self.assertEqual(membership.role, 'AP')
        self.assertEqual(Membership.objects.filter(user=self.user).count(), 1)

    def test_safe_deletion_history_and_authorization(self):
        invite = Invitation.objects.create(email='x@example.com', department=self.dept, inviter=self.admin)
        delivery = InvitationDelivery.objects.create(invitation=invite)
        url = reverse('delete_department', args=[self.dept.pk])
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertTrue(Department.objects.filter(pk=self.dept.pk).exists())
        csrf = Client(enforce_csrf_checks=True); csrf.force_login(self.admin)
        self.assertEqual(csrf.post(url).status_code, 403)
        self.assertEqual(self.client.post(url).status_code, 302)
        delivery.refresh_from_db(); self.assertIsNone(delivery.invitation_id)
        self.assertEqual(delivery.status, 'cancelled')
        self.assertIsNone(AuditLog.objects.get(event_type='department.deleted').department_id)

    def test_evidence_blocks_all_deletion_paths(self):
        meeting = Meeting.objects.create(department=self.dept, title='Evidence')
        attendance = Attendance.objects.create(meeting=meeting, user=self.user)
        request = RequestFactory().post('/'); request.user = self.admin
        self.client.force_login(self.admin)
        cases = [('status', 'Finished'), ('status', 'Archived'), ('has_signed', True),
                 ('cryptographic_signature', 'signature'), ('signed_at', timezone.now())]
        for field, value in cases:
            model = Meeting if field == 'status' else Attendance
            pk = meeting.pk if field == 'status' else attendance.pk
            model.objects.filter(pk=pk).update(**{field: value})
            for operation in (lambda: Department.objects.filter(pk=self.dept.pk).delete(),
                              lambda: admin.site._registry[Department].delete_model(request, self.dept)):
                with self.assertRaises(PermissionDenied), transaction.atomic(): operation()
            self.assertEqual(self.client.post(reverse('delete_department', args=[self.dept.pk])).status_code, 400)
            model.objects.filter(pk=pk).update(**{field: 'Draft' if field == 'status' else False if field == 'has_signed' else None})
        VerificationQR.objects.create(attendance=attendance, token_hash='hash', encrypted_token='encrypted')
        with self.assertRaises(PermissionDenied), transaction.atomic(): self.dept.delete()
        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())


class DepartmentDeletionConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='creator')
        self.admin = User.objects.create_user(username='global', is_admin=True)
        self.dept = Department.objects.create(name='Private', contact_email='private@example.com')

    def test_committed_concurrent_evidence_after_collection_blocks_delete(self):
        from concurrent.futures import ThreadPoolExecutor
        from django.db import connections
        from django.db.models.deletion import Collector
        user = User.objects.create_user(username='concurrent')
        department = Department.objects.create(name='Concurrent')
        meeting = Meeting.objects.create(department=department, title='Concurrent')
        attendance = Attendance.objects.create(meeting=meeting, user=user)
        collector = Collector(using='default'); collector.collect([department])

        def sign():
            try:
                with transaction.atomic():
                    from meetings.attendance_integrity import lock_mutable_meetings
                    lock_mutable_meetings([meeting.pk])
                    Attendance.objects.select_for_update().get(pk=attendance.pk)
                    Attendance.objects.filter(pk=attendance.pk).update(has_signed=True)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(sign).result(timeout=10)
        with self.assertRaises(PermissionDenied):
            collector.delete()
        self.assertTrue(Department.objects.filter(pk=department.pk).exists())
        self.assertTrue(Attendance.objects.get(pk=attendance.pk).has_signed)

    def test_evidence_added_after_cascade_collection_is_revalidated(self):
        from django.db.models.deletion import Collector
        meeting = Meeting.objects.create(department=self.dept, title='Race')
        attendance = Attendance.objects.create(meeting=meeting, user=self.user)
        collector = Collector(using='default')
        collector.collect([self.dept])
        # Represents a signing writer winning between collection and deletion.
        Attendance.objects.filter(pk=attendance.pk).update(cryptographic_signature='new evidence')
        with self.assertRaises(PermissionDenied), transaction.atomic():
            collector.delete()
        self.assertTrue(Department.objects.filter(pk=self.dept.pk).exists())
        self.assertEqual(Attendance.objects.get(pk=attendance.pk).cryptographic_signature, 'new evidence')

    def test_bulk_admin_deletion_rolls_back_audits(self):
        safe = Department.objects.create(name='Safe')
        Meeting.objects.create(department=self.dept, title='Protected', status='Finished')
        request = RequestFactory().post('/'); request.user = self.admin
        with self.assertRaises(PermissionDenied):
            admin.site._registry[Department].delete_queryset(request, Department.objects.all())
        self.assertTrue(Department.objects.filter(pk=safe.pk).exists())
        self.assertFalse(AuditLog.objects.filter(event_type='department.deleted').exists())
