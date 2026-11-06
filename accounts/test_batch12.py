from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, Client, RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from django.core import mail
from allauth.account.models import EmailAddress
from .models import User, Department, Membership, Invitation
from meetings.models import AuditLog


@override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}})
class Batch12Tests(TestCase):
    def setUp(self):
        self.department = Department.objects.create(name='Inviting department')
        self.ap = User.objects.create_user(username='ap')
        Membership.objects.create(user=self.ap, department=self.department, role='AP')
        self.user = User.objects.create_user(username='recipient', password='password')
        self.invite = Invitation.objects.create(email='recipient@example.com', department=self.department, inviter=self.ap)
        self.url = reverse('accept_invitation', args=[self.invite.token])

    def verify(self, primary=False):
        return EmailAddress.objects.create(user=self.user, email=self.invite.email, verified=True, primary=primary)

    def test_delivery_and_url(self):
        self.client.force_login(self.ap)
        self.assertEqual(self.client.post(reverse('invite_member', args=[self.department.pk]),
            {'email': self.invite.email, 'role': 'O'}).status_code, 302)
        new = Invitation.objects.get(accepted=False)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('http://testserver' + reverse('accept_invitation', args=[new.token]), mail.outbox[0].body)
        self.assertIn(self.department.name, mail.outbox[0].body)
        self.assertIn('seven days', mail.outbox[0].body)
        self.assertFalse(Invitation.objects.filter(pk=self.invite.pk).exists())

    def test_failed_replacement_preserves_old(self):
        self.client.force_login(self.ap)
        with patch('django.core.mail.send_mail', side_effect=RuntimeError('PRIVATE PASSWORD')):
            response = self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': self.invite.email, 'role': 'O'})
        self.assertContains(response, 'could not be sent')
        self.assertNotContains(response, 'PRIVATE PASSWORD')
        self.assertEqual(Invitation.objects.count(), 1)
        self.assertFalse(AuditLog.objects.exists())

    def test_get_and_csrf(self):
        self.verify()
        self.client.force_login(self.user)
        self.assertContains(self.client.get(self.url), 'Accept invitation')
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)
        self.assertFalse(Membership.objects.filter(user=self.user).exists())
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(self.url).status_code, 403)
        self.assertEqual(self.client.put(self.url).status_code, 405)

    def test_primary_and_secondary_verified(self):
        self.verify(primary=False)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.url).status_code, 302)
        self.assertEqual(Membership.objects.get(user=self.user).role, 'O')
        self.assertEqual(self.client.post(self.url).status_code, 400)
        self.assertEqual(AuditLog.objects.filter(event_type='invitation.accepted').count(), 1)

    def test_wrong_and_unverified(self):
        address = EmailAddress.objects.create(user=self.user, email=self.invite.email, verified=False)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.url).status_code, 403)
        address.delete()
        EmailAddress.objects.create(user=self.user, email='other@example.com', verified=True)
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)

    def test_invalid_states(self):
        self.verify(True)
        self.client.force_login(self.user)
        for field, value in (('expires_at', timezone.now() - timedelta(seconds=1)), ('accepted', True)):
            old = getattr(self.invite, field)
            setattr(self.invite, field, value)
            self.invite.save()
            self.assertEqual(self.client.post(self.url).status_code, 400)
            setattr(self.invite, field, old)
            self.invite.save()
        self.department.is_active = False
        self.department.save()
        self.assertEqual(self.client.post(self.url).status_code, 400)
        self.invite.delete()
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_membership_preservation(self):
        self.verify()
        member = Membership.objects.create(user=self.user, department=self.department, role='AP')
        other = Department.objects.create(name='Other')
        Membership.objects.create(user=self.user, department=other, role='O')
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.url).status_code, 302)
        member.refresh_from_db()
        self.assertEqual(member.role, 'AP')
        self.assertEqual(Membership.objects.filter(user=self.user).count(), 2)

    def test_audit_failure_rolls_back(self):
        self.verify()
        self.client.force_login(self.user)
        with patch('accounts.views.record', side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):
                self.client.post(self.url)
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)
        self.assertFalse(Membership.objects.filter(user=self.user).exists())

    def test_login_and_session_recovery(self):
        self.verify()
        self.client.get(self.url)
        response = self.client.post(reverse('account_login'), {'login': 'recipient', 'password': 'password', 'next': 'https://evil.invalid'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.url)
        self.client.logout()
        self.assertContains(self.client.get(self.url), 'Register')
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)

    def test_verification_return_and_google_identity(self):
        from .adapter import InvitationAccountAdapter
        from allauth.socialaccount.providers.google.provider import GoogleProvider
        request = RequestFactory().get('/')
        request.session = {'pending_invite_token': self.invite.token}
        request.user = self.user
        from allauth.core.context import request_context
        with request_context(request):
            adapter = InvitationAccountAdapter(request)
            self.assertEqual(adapter.get_email_verification_redirect_url(None), self.url)
        # Google declares verification, but it must still be a matching address on this account.
        addresses = GoogleProvider.extract_email_addresses(None, {'email': self.invite.email, 'email_verified': True})
        self.assertTrue(addresses[0].verified)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.url).status_code, 403)

    def test_signup_verification_continuation(self):
        from allauth.account.models import EmailConfirmationHMAC
        self.client.get(self.url)
        response = self.client.post(reverse('account_signup'), {'username': 'newrecipient',
            'email': self.invite.email, 'password1': 'Strong-pass-987', 'password2': 'Strong-pass-987'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.url)
        address = EmailAddress.objects.get(user__username='newrecipient', email=self.invite.email)
        self.assertFalse(address.verified)
        confirmation = reverse('account_confirm_email', args=[EmailConfirmationHMAC(address).key])
        response = self.client.post(confirmation)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.url)
        self.assertEqual(self.client.post(self.url).status_code, 302)

    def test_conditional_consumption_loser(self):
        from django.db.models.query import QuerySet
        original = QuerySet.update
        self.verify()
        self.client.force_login(self.user)
        def lose(queryset, **kwargs):
            if queryset.model is Invitation and kwargs.get('accepted'):
                return 0
            return original(queryset, **kwargs)
        with patch.object(QuerySet, 'update', lose):
            self.assertEqual(self.client.post(self.url).status_code, 400)
        self.assertFalse(Membership.objects.filter(user=self.user).exists())
        self.assertFalse(AuditLog.objects.exists())

    def test_google_post_login_uses_internal_destination(self):
        from .adapter import InvitationAccountAdapter
        request = RequestFactory().get('/')
        request.session = {'pending_invite_token': self.invite.token}
        with patch('allauth.account.adapter.DefaultAccountAdapter.post_login') as finish:
            InvitationAccountAdapter().post_login(request, self.user, redirect_url='https://evil.invalid')
        self.assertEqual(finish.call_args.kwargs['redirect_url'], self.url)
