from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from django.test import TransactionTestCase, override_settings
from django.db import transaction, IntegrityError
from django.core import mail
from django.core.management import call_command, CommandError
from django.utils import timezone
from django.urls import reverse
from allauth.account.models import EmailAddress, EmailConfirmationHMAC
from .models import User, VerificationEmailDelivery as Delivery
from .verification_delivery import enqueue, claim, finish, process_one, eligible
from .account_status import change_account_status


@override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}})
class VerificationDeliveryTests(TransactionTestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='recipient')
        self.admin = User.objects.create_user(username='controller', is_admin=True)
        self.address = EmailAddress.objects.create(user=self.user, email='owner@example.com')

    def due(self, row):
        Delivery.objects.filter(pk=row.pk).update(next_attempt_at=timezone.now()-timedelta(seconds=1))

    def process(self, row):
        return process_one(row.pk, 'https://testserver')

    def test_enqueue_coalesces_and_rolls_back_with_caller(self):
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                row = enqueue(self.address, signup=True)
                self.assertEqual(enqueue(self.address).pk, row.pk)
                with self.assertRaises(RuntimeError): self.process(row)
                self.assertEqual(len(mail.outbox), 0)
                raise RuntimeError()
        self.assertFalse(Delivery.objects.exists())
        row = enqueue(self.address)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Delivery.objects.create(address=self.address, original_address_id=self.address.pk,
                original_user_id=self.user.pk, recipient=self.address.email, session_version=0)
        self.assertEqual(self.process(row), 'submitted')
        self.assertNotEqual(enqueue(self.address).pk, row.pk)

    def test_fresh_links_validate_and_secrets_are_not_stored(self):
        row = enqueue(self.address, signup=True)
        from .verification_delivery import render_message
        now = timezone.now().timestamp()
        with patch('django.core.signing.time.time', return_value=now):
            first = render_message(row, 'https://testserver')
        with patch('django.core.signing.time.time', return_value=now+60):
            second = render_message(row, 'https://testserver')
        self.assertNotEqual(first.body, second.body)
        import re
        url = re.search(r'https://testserver/accounts/auth/confirm-email/([^/\s]+)/', first.body)
        self.assertIsNotNone(url)
        self.assertEqual(EmailConfirmationHMAC.from_key(url.group(1)).email_address.pk, self.address.pk)
        self.assertNotIn(url.group(1), str(Delivery.objects.values().get(pk=row.pk)))
        self.assertEqual(first.to, [self.address.email])

    def test_claim_recovery_and_stale_worker(self):
        row = enqueue(self.address)
        first = claim(row.pk)
        self.assertIsNone(claim(row.pk))
        Delivery.objects.filter(pk=row.pk).update(lease_expires_at=timezone.now()-timedelta(seconds=1))
        second = claim(row.pk)
        self.assertNotEqual(first, second)
        self.assertEqual(finish(row.pk, first, 'submitted'), 0)
        self.assertEqual(finish(row.pk, second, 'submitted'), 1)

    def test_five_expired_leases_retire_without_sixth_claim_or_submission(self):
        row = enqueue(self.address)
        clock = timezone.now()
        owners = []
        with patch('accounts.verification_delivery.timezone.now', side_effect=lambda: clock), \
                patch('accounts.verification_delivery.render_message') as render:
            for attempt in range(1, 6):
                owners.append(claim(row.pk))
                self.assertIsNotNone(owners[-1])
                row.refresh_from_db(); self.assertEqual(row.attempts, attempt)
                self.assertIsNone(claim(row.pk))  # Live claims cannot be stolen.
                clock += timedelta(seconds=121)
            self.assertIsNone(claim(row.pk))
            row.refresh_from_db()
            self.assertEqual(row.status, 'failed')
            self.assertEqual(row.attempts, 5)
            self.assertIsNone(row.claim_id)
            self.assertFalse(Delivery.objects.filter(pk=row.pk).filter(eligible(clock)).exists())
            self.assertIsNone(self.process(row))
            for owner in owners:
                self.assertEqual(finish(row.pk, owner, 'submitted'), 0)
            render.assert_not_called()
        self.assertEqual(len(mail.outbox), 0)

    def test_command_retires_exhausted_and_expired_work_without_claiming(self):
        row = enqueue(self.address)
        Delivery.objects.filter(pk=row.pk).update(attempts=5,
            next_attempt_at=timezone.now()+timedelta(hours=1))
        with patch('accounts.verification_delivery.render_message') as render:
            output = StringIO()
            call_command('process_verification_deliveries', base_url='https://testserver', stdout=output)
            self.assertIn('failed=1', output.getvalue())
            row.refresh_from_db(); self.assertEqual(row.attempts, 5)
            expired = enqueue(self.address)
            Delivery.objects.filter(pk=expired.pk).update(expires_at=timezone.now()-timedelta(seconds=1),
                next_attempt_at=timezone.now()+timedelta(hours=1))
            self.assertEqual(self.process(expired), 'expired')
            expired.refresh_from_db(); self.assertEqual(expired.attempts, 0)
            render.assert_not_called()

    def test_lease_expiry_during_last_lifecycle_check_prevents_smtp(self):
        row = enqueue(self.address)
        clock = timezone.now()
        from .verification_delivery import invalid_status
        checks = []
        def validate(current):
            nonlocal clock
            result = invalid_status(current)
            checks.append(current.claim_id)
            if len(checks) == 2:
                clock += timedelta(seconds=121)
            return result
        with patch('accounts.verification_delivery.timezone.now', side_effect=lambda: clock), \
                patch('accounts.verification_delivery.invalid_status', side_effect=validate), \
                patch('accounts.verification_delivery.render_message') as render:
            self.assertIsNone(self.process(row))
            render.return_value.send.assert_not_called()
            new_owner = claim(row.pk)
            self.assertIsNotNone(new_owner)
            self.assertEqual(finish(row.pk, checks[0], 'submitted'), 0)
            row.refresh_from_db(); self.assertEqual(row.attempts, 2)

    def test_lease_expiry_during_smtp_cannot_overwrite_reclaimed_owner(self):
        row = enqueue(self.address)
        clock = timezone.now()
        reclaimed = []
        def smtp():
            nonlocal clock
            clock += timedelta(seconds=121)
            reclaimed.append(claim(row.pk))
            return 1  # Submission may have happened; it cannot be rolled back.
        with patch('accounts.verification_delivery.timezone.now', side_effect=lambda: clock), \
                patch('accounts.verification_delivery.render_message') as render:
            render.return_value.send.side_effect = smtp
            self.assertIsNone(self.process(row))
            render.return_value.send.assert_called_once()
            row.refresh_from_db()
            self.assertEqual(row.claim_id, reclaimed[0])
            self.assertEqual(row.status, 'processing')
            self.assertEqual(row.attempts, 2)

    def test_status_audit_rollback_and_inflight_cancellation(self):
        row = enqueue(self.address)
        owner = claim(row.pk)
        with patch('accounts.account_status.record', side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                change_account_status(self.admin, self.user.pk, False)
        row.refresh_from_db(); self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertEqual(row.status, 'processing')
        self.assertEqual(row.claim_id, owner)
        change_account_status(self.admin, self.user.pk, False)
        row.refresh_from_db(); self.assertEqual(row.status, 'cancelled')
        self.assertEqual(finish(row.pk, owner, 'submitted'), 0)
        self.assertIsNone(enqueue(self.address))
        self.address.verified = True; self.address.save()
        self.assertIsNone(enqueue(self.address))

    def test_retry_zero_exception_budget_and_expiry(self):
        row = enqueue(self.address)
        with patch('django.core.mail.message.EmailMessage.send', return_value=0):
            for attempt in range(1, 6):
                self.assertEqual(self.process(row), 'failed' if attempt == 5 else 'retried')
                row.refresh_from_db(); self.assertEqual(row.attempts, attempt)
                self.assertLessEqual((row.next_attempt_at-timezone.now()).total_seconds(), 3600)
                self.due(row)
        self.assertIsNone(self.process(row))
        row = enqueue(self.address)
        with patch('django.core.mail.message.EmailMessage.send', side_effect=RuntimeError('SECRET PASSWORD')):
            self.assertEqual(self.process(row), 'retried')
        row.refresh_from_db(); self.assertNotIn('SECRET', row.last_error)
        Delivery.objects.filter(pk=row.pk).update(expires_at=timezone.now()-timedelta(seconds=1))
        self.due(row); self.assertEqual(self.process(row), 'expired')

    def test_lifecycle_cancellation_and_history(self):
        for state in ('verified', 'email', 'owner', 'removed', 'inactive', 'deleted'):
            with self.subTest(state=state):
                user = User.objects.create_user(username='u'+state)
                address = EmailAddress.objects.create(user=user, email=state+'@example.com')
                row = enqueue(address)
                if state in ('verified', 'email', 'owner'):
                    if state == 'verified': address.verified = True
                    if state == 'email': address.email = 'changed@example.com'
                    if state == 'owner': address.user = self.admin
                    address.save()
                elif state == 'removed': address.delete()
                elif state == 'deleted': user.delete()
                else:
                    change_account_status(self.admin, user.pk, False)
                    change_account_status(self.admin, user.pk, True)
                row.refresh_from_db(); self.assertEqual(row.status, 'cancelled')
                self.assertIsNone(self.process(row))
        self.assertEqual(len(mail.outbox), 0)

    def test_presend_revalidation_and_stale_completion(self):
        row = enqueue(self.address)
        from .verification_delivery import render_message
        def verify_before_send(*args):
            message = render_message(*args)
            EmailAddress.objects.filter(pk=self.address.pk).update(verified=True)
            return message
        with patch('accounts.verification_delivery.render_message', side_effect=verify_before_send):
            self.assertEqual(self.process(row), 'cancelled')
        self.assertEqual(len(mail.outbox), 0)

    def test_allauth_signup_add_address_enqueue_without_submission(self):
        response = self.client.post(reverse('account_signup'), {'username': 'newrecipient',
            'email': 'new@example.com', 'password1': 'Strong-pass-987', 'password2': 'Strong-pass-987'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Delivery.objects.filter(recipient='new@example.com', signup=True).exists())
        self.client.force_login(self.user)
        response = self.client.post(reverse('account_email'), {'email': 'extra@example.com', 'action_add': ''})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Delivery.objects.filter(recipient='extra@example.com', signup=False).exists())
        self.assertEqual(len(mail.outbox), 0)

    def test_command_bounds_and_summary(self):
        row = enqueue(self.address)
        for options in ({'limit': 0, 'base_url': 'https://testserver'},
                        {'limit': 1001, 'base_url': 'https://testserver'},
                        {'limit': 1, 'base_url': 'https://user:secret@testserver'}):
            with self.assertRaises(CommandError): call_command('process_verification_deliveries', **options)
        output = StringIO()
        call_command('process_verification_deliveries', base_url='https://testserver', limit=1, stdout=output)
        self.assertIn('submitted=1', output.getvalue())
        self.assertNotIn('confirm-email', output.getvalue())

    def test_concurrent_enqueue_and_claim(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from django.db import connections, OperationalError
        barrier = Barrier(2)
        def request():
            try:
                address = EmailAddress.objects.get(pk=self.address.pk)
                barrier.wait(timeout=10)
                try:
                    return enqueue(address).pk
                except OperationalError:
                    return None  # SQLite rejects contention; a fresh request retries safely.
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(request) for _ in range(2)]
            results = [f.result(timeout=20) for f in futures]
        row = enqueue(self.address)
        self.assertEqual(Delivery.objects.filter(status__in=('pending', 'processing')).count(), 1)
        self.assertTrue(all(pk is None or pk == row.pk for pk in results))
        Delivery.objects.filter(pk=row.pk).update(attempts=4)  # Compete for the final allowed claim.
        barrier = Barrier(2)
        def worker():
            try:
                barrier.wait(timeout=10)
                try: return claim(row.pk)
                except OperationalError: return None
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            owners = [f.result(timeout=20) for f in futures]
        self.assertEqual(sum(owner is not None for owner in owners), 1)
        row.refresh_from_db(); self.assertEqual(row.attempts, 5)
        self.assertEqual(row.status, 'processing')

    def test_unrelated_adapter_mail_and_render_context_remain_intact(self):
        from .adapter import InvitationAccountAdapter
        from allauth.core.context import request_context
        from django.test import RequestFactory
        request = RequestFactory().get('/')
        with request_context(request):
            InvitationAccountAdapter().send_mail('account/email/email_confirmation', self.address.email,
                {'user': self.user, 'activate_url': 'https://testserver/example'})
        self.assertEqual(len(mail.outbox), 1)
        self.assertFalse(Delivery.objects.exists())
        row = enqueue(self.address, signup=True)
        from .verification_delivery import render_message
        from allauth.account.adapter import DefaultAccountAdapter
        original = DefaultAccountAdapter.render_mail
        with patch('allauth.account.adapter.DefaultAccountAdapter.render_mail', autospec=True,
                   side_effect=original) as rendered:
            render_message(row, 'https://testserver')
        self.assertEqual(rendered.call_args.args[1], 'account/email/email_confirmation_signup')
