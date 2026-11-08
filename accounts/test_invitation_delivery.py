from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.db import transaction
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from .models import User, Department, Membership, Invitation, InvitationDelivery
from .invitation_delivery import claim, finish, process_one


@override_settings(INVITATION_DELIVERY_MAX_ATTEMPTS=2,
    MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}})
class InvitationDeliveryTests(TransactionTestCase):
    def setUp(self):
        self.department = Department.objects.create(name='Delivery')
        self.ap = User.objects.create_user(username='delivery-ap')
        self.officer = User.objects.create_user(username='delivery-officer')
        self.admin = User.objects.create_user(username='delivery-admin', is_admin=True)
        self.other = User.objects.create_user(username='other-ap')
        other_dept = Department.objects.create(name='Other delivery')
        Membership.objects.create(user=self.ap, department=self.department, role='AP')
        Membership.objects.create(user=self.officer, department=self.department, role='O')
        Membership.objects.create(user=self.other, department=other_dept, role='AP')
        self.invitation = Invitation.objects.create(email='recipient@example.com', department=self.department, inviter=self.ap)
        self.delivery = InvitationDelivery.objects.create(invitation=self.invitation)

    def process(self):
        return process_one(self.delivery.pk, 'https://testserver')

    def due(self):
        InvitationDelivery.objects.filter(pk=self.delivery.pk).update(next_attempt_at=timezone.now()-timedelta(seconds=1))

    def test_creation_commit_and_no_precommit_submission(self):
        self.client.force_login(self.ap)
        with patch('accounts.invitation_delivery.send_mail') as send:
            with transaction.atomic():
                response = self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': 'new@example.com', 'role': 'O'})
                self.assertEqual(response.status_code, 302)
                self.assertTrue(InvitationDelivery.objects.filter(invitation__email='new@example.com').exists())
                send.assert_not_called()
                with self.assertRaises(RuntimeError):
                    self.process()
            send.assert_not_called()
        self.assertTrue(InvitationDelivery.objects.filter(invitation__email='new@example.com').exists())

    def test_replacement_rollback_restores_old_and_outbox(self):
        self.client.force_login(self.ap)
        with patch('accounts.invitation_delivery.send_mail') as send:
            with self.assertRaises(RuntimeError):
                with transaction.atomic():
                    self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': self.invitation.email, 'role': 'O'})
                    raise RuntimeError('rollback after queued replacement')
            send.assert_not_called()
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, 'pending')
        self.assertEqual(self.delivery.invitation_id, self.invitation.pk)
        self.assertEqual(Invitation.objects.count(), 1)
        self.assertEqual(InvitationDelivery.objects.count(), 1)

    def test_success_content_and_state(self):
        with patch('accounts.invitation_delivery.send_mail', return_value=1) as send:
            self.assertEqual(self.process(), 'submitted')
        self.assertIn(reverse('accept_invitation', args=[self.invitation.token]), send.call_args.args[1])
        self.assertIn('seven days', send.call_args.args[1])
        self.delivery.refresh_from_db()
        self.assertIsNotNone(self.delivery.submitted_at)
        self.assertIsNone(self.delivery.claim_id)
        self.assertEqual(self.delivery.attempts, 1)

    def test_failure_backoff_retry_same_identity_and_limit(self):
        original = (self.invitation.pk, self.invitation.token, self.invitation.expires_at)
        for expected in ('retried', 'failed'):
            self.due()
            with patch('accounts.invitation_delivery.send_mail', side_effect=RuntimeError('SECRET SMTP PASSWORD')):
                self.assertEqual(self.process(), expected)
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.attempts, 2)
        self.assertGreater(self.delivery.next_attempt_at, timezone.now())
        self.assertNotIn('SECRET', self.delivery.last_error)
        self.invitation.refresh_from_db()
        self.assertEqual((self.invitation.pk, self.invitation.token, self.invitation.expires_at), original)
        self.assertEqual(Invitation.objects.count(), 1)

    def test_ambiguous_failure_retries_same_token(self):
        bodies = []
        def ambiguous(*args, **kwargs):
            bodies.append(args[1])
            raise OSError('accepted then disconnected')
        with patch('accounts.invitation_delivery.send_mail', side_effect=ambiguous):
            self.assertEqual(self.process(), 'retried')
        self.due()
        with patch('accounts.invitation_delivery.send_mail', side_effect=lambda *a, **k: bodies.append(a[1]) or 1):
            self.assertEqual(self.process(), 'submitted')
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(Invitation.objects.count(), 1)

    def test_invalid_invitations_never_sent(self):
        for state in ('expired', 'consumed', 'inactive', 'deleted'):
            with self.subTest(state=state):
                invitation = Invitation.objects.create(email='invalid@example.com', department=self.department, inviter=self.ap)
                delivery = InvitationDelivery.objects.create(invitation=invitation)
                if state == 'expired':
                    invitation.expires_at = timezone.now()-timedelta(seconds=1)
                    invitation.save()
                elif state == 'consumed':
                    invitation.accepted = True
                    invitation.save()
                elif state == 'inactive':
                    Department.objects.filter(pk=self.department.pk).update(is_active=False)
                else:
                    invitation.delete()
                with patch('accounts.invitation_delivery.send_mail') as send:
                    process_one(delivery.pk, 'https://testserver')
                    send.assert_not_called()
                delivery.refresh_from_db()
                self.assertEqual(delivery.status, 'expired' if state == 'expired' else 'cancelled')
                Department.objects.filter(pk=self.department.pk).update(is_active=True)

    def test_replacement_cancels_history_and_old_link(self):
        self.client.force_login(self.ap)
        old_token = self.invitation.token
        self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': self.invitation.email, 'role': 'O'})
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, 'cancelled')
        self.assertIsNone(self.delivery.invitation_id)
        self.assertEqual(InvitationDelivery.objects.filter(status='pending').count(), 1)
        self.assertEqual(self.client.get(reverse('accept_invitation', args=[old_token])).status_code, 404)
        with patch('accounts.invitation_delivery.send_mail') as send:
            self.process()
            send.assert_not_called()

    def test_claim_exclusion_reclaim_and_stale_completion(self):
        first = claim(self.delivery.pk)
        self.assertIsNotNone(first)
        self.assertIsNone(claim(self.delivery.pk))
        InvitationDelivery.objects.filter(pk=self.delivery.pk).update(lease_expires_at=timezone.now()-timedelta(seconds=1))
        self.assertEqual(finish(self.delivery.pk, first, 'submitted'), 0)
        second = claim(self.delivery.pk)
        self.assertNotEqual(first, second)
        self.assertEqual(finish(self.delivery.pk, first, 'submitted'), 0)
        self.assertEqual(finish(self.delivery.pk, second, 'submitted'), 1)

    def test_authorized_retry_and_legacy_queue(self):
        for actor in (self.ap, self.admin):
            InvitationDelivery.objects.filter(pk=self.delivery.pk).update(status='failed')
            self.client.force_login(actor)
            response = self.client.post(reverse('retry_invitation_delivery', args=[self.invitation.pk]))
            self.assertEqual(response.status_code, 302)
            self.delivery.refresh_from_db()
            self.assertEqual(self.delivery.status, 'pending')
        legacy = Invitation.objects.create(email='legacy@example.com', department=self.department, inviter=self.ap)
        self.assertEqual(self.client.post(reverse('retry_invitation_delivery', args=[legacy.pk])).status_code, 302)
        self.assertTrue(InvitationDelivery.objects.filter(invitation=legacy).exists())

    def test_retry_denials_and_terminal_states(self):
        url = reverse('retry_invitation_delivery', args=[self.invitation.pk])
        for actor in (self.officer, self.other):
            self.client.force_login(actor)
            self.assertEqual(self.client.post(url).status_code, 404)
        self.client.force_login(self.ap)
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url).status_code, 400)
        self.invitation.accepted = True
        self.invitation.save()
        self.assertEqual(self.client.post(url).status_code, 400)

    def test_history_survives_delete_and_command_counts(self):
        with patch('accounts.invitation_delivery.send_mail', return_value=0):
            out = StringIO()
            call_command('process_invitation_deliveries', base_url='https://testserver', limit=1, stdout=out)
        self.assertIn('retried=1', out.getvalue())
        self.invitation.delete()
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, 'cancelled')
        self.assertIsNone(self.delivery.invitation_id)

    def test_new_invitation_rollback_and_audit_failure(self):
        from meetings.models import AuditLog
        self.client.force_login(self.ap)
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': 'rollback@example.com', 'role': 'O'})
                self.assertTrue(InvitationDelivery.objects.filter(invitation__email='rollback@example.com').exists())
                raise RuntimeError('rollback')
        self.assertFalse(Invitation.objects.filter(email='rollback@example.com').exists())
        self.assertFalse(InvitationDelivery.objects.filter(invitation__email='rollback@example.com').exists())
        with patch('accounts.views.record', side_effect=RuntimeError('audit failed')):
            self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': self.invitation.email, 'role': 'O'})
        self.assertTrue(Invitation.objects.filter(pk=self.invitation.pk).exists())
        self.assertEqual(InvitationDelivery.objects.count(), 1)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_schedule_and_terminal_submission_are_not_reprocessed(self):
        InvitationDelivery.objects.filter(pk=self.delivery.pk).update(next_attempt_at=timezone.now()+timedelta(hours=1))
        with patch('accounts.invitation_delivery.send_mail') as send:
            self.assertIsNone(self.process())
            send.assert_not_called()
        self.due()
        with patch('accounts.invitation_delivery.send_mail', return_value=1) as send:
            self.assertEqual(self.process(), 'submitted')
            self.assertIsNone(self.process())
            self.assertEqual(send.call_count, 1)
        self.assertEqual(Invitation.objects.count(), 1)

    def test_replacement_during_submission_does_not_overwrite_cancellation(self):
        def deleted(*args, **kwargs):
            self.invitation.delete()
            return 1
        with patch('accounts.invitation_delivery.send_mail', side_effect=deleted):
            self.assertIsNone(self.process())
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, 'cancelled')
        self.assertIsNone(self.delivery.submitted_at)

    def test_retry_rejects_expired_inactive_missing_and_keeps_identity(self):
        url = reverse('retry_invitation_delivery', args=[self.invitation.pk])
        self.client.force_login(self.ap)
        InvitationDelivery.objects.filter(pk=self.delivery.pk).update(status='failed')
        original = (self.invitation.token, self.invitation.expires_at)
        self.assertEqual(self.client.post(url).status_code, 302)
        self.invitation.refresh_from_db()
        self.assertEqual((self.invitation.token, self.invitation.expires_at), original)
        self.invitation.expires_at = timezone.now()-timedelta(seconds=1)
        self.invitation.save()
        self.assertEqual(self.client.post(url).status_code, 400)
        self.invitation.expires_at = timezone.now()+timedelta(days=1)
        self.invitation.save()
        Department.objects.filter(pk=self.department.pk).update(is_active=False)
        self.assertEqual(self.client.post(url).status_code, 400)
        self.invitation.delete()
        self.assertEqual(self.client.post(url).status_code, 404)

    def test_failed_and_submitted_history_survive_deletion(self):
        for status in ('failed', 'submitted', 'expired'):
            invitation = Invitation.objects.create(email='history@example.com', department=self.department, inviter=self.ap)
            delivery = InvitationDelivery.objects.create(invitation=invitation, status=status)
            invitation.delete()
            delivery.refresh_from_db()
            self.assertEqual(delivery.status, status)
            self.assertIsNone(delivery.invitation_id)

    def test_command_bounds_and_configuration_fail_closed(self):
        from django.core.management.base import CommandError
        for options in ({'limit': 0, 'base_url': 'https://testserver'},
                        {'limit': 1001, 'base_url': 'https://testserver'},
                        {'limit': 1, 'base_url': 'https://user:password@testserver'}):
            with self.subTest(options=options), patch('accounts.invitation_delivery.send_mail') as send:
                with self.assertRaises(CommandError):
                    call_command('process_invitation_deliveries', **options)
                send.assert_not_called()
        Invitation.objects.create(email='second@example.com', department=self.department, inviter=self.ap)
        InvitationDelivery.objects.create(invitation=Invitation.objects.get(email='second@example.com'))
        with patch('accounts.invitation_delivery.send_mail', return_value=1) as send:
            call_command('process_invitation_deliveries', base_url='https://testserver', limit=1, stdout=StringIO())
            self.assertEqual(send.call_count, 1)
        self.assertEqual(InvitationDelivery.objects.filter(status='pending').count(), 1)
