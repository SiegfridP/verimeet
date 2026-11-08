from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, Client, RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from django.core import mail
from allauth.account.models import EmailAddress
from .models import User, Department, Membership, Invitation, InvitationDelivery
from meetings.models import AuditLog


@override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}})
class Batch12Tests(TestCase):
    def setUp(self):
        from .test_fixtures import signature_storage, complete_onboarding
        signature_storage(self)
        self.department = Department.objects.create(name='Inviting department')
        self.ap = User.objects.create_user(username='ap')
        Membership.objects.create(user=self.ap, department=self.department, role='AP')
        self.user = User.objects.create_user(username='recipient', password='password')
        complete_onboarding(self.ap, self.user)
        self.invite = Invitation.objects.create(email='recipient@example.com', department=self.department, inviter=self.ap)
        self.url = reverse('accept_invitation', args=[self.invite.token])

    def verify(self, primary=False):
        return EmailAddress.objects.create(user=self.user, email=self.invite.email, verified=True, primary=primary)

    def test_delivery_and_url(self):
        self.client.force_login(self.ap)
        self.assertEqual(self.client.post(reverse('invite_member', args=[self.department.pk]),
            {'email': self.invite.email, 'role': 'O'}).status_code, 302)
        new = Invitation.objects.get(accepted=False)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(InvitationDelivery.objects.get(invitation=new).status, 'pending')
        self.assertFalse(Invitation.objects.filter(pk=self.invite.pk).exists())

    def test_failed_queue_replacement_preserves_old(self):
        self.client.force_login(self.ap)
        with patch('accounts.models.InvitationDelivery.objects.create', side_effect=RuntimeError('PRIVATE PASSWORD')):
            response = self.client.post(reverse('invite_member', args=[self.department.pk]), {'email': self.invite.email, 'role': 'O'})
        self.assertContains(response, 'could not be queued')
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
        response = self.client.post(reverse('account_login'), {'login': 'recipient', 'password': 'password', 'next': self.url})
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
        request.session = {'pending_invite_token': self.invite.token, 'invite_verification_intent': [self.invite.token, self.user.pk]}
        request.user = self.user
        from allauth.core.context import request_context
        with request_context(request):
            adapter = InvitationAccountAdapter(request)
            self.assertEqual(adapter.get_email_verification_redirect_url(EmailAddress(user=self.user, email=self.invite.email)), self.url)
        # Google declares verification, but it must still be a matching address on this account.
        addresses = GoogleProvider.extract_email_addresses(None, {'email': self.invite.email, 'email_verified': True})
        self.assertTrue(addresses[0].verified)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(self.url).status_code, 403)

    def test_signup_verification_continuation(self):
        from allauth.account.models import EmailConfirmationHMAC
        self.client.get(self.url)
        response = self.client.post(reverse('account_signup'), {'username': 'newrecipient',
            'email': self.invite.email, 'password1': 'Strong-pass-987', 'password2': 'Strong-pass-987', 'next': self.url})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.url)
        address = EmailAddress.objects.get(user__username='newrecipient', email=self.invite.email)
        self.assertFalse(address.verified)
        self.assertFalse(Membership.objects.filter(user=address.user).exists())
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)
        confirmation = reverse('account_confirm_email', args=[EmailConfirmationHMAC(address).key])
        response = self.client.post(confirmation)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.url)

        # Registration and email verification do not complete onboarding or join.
        from .signatures import complete
        from .test_onboarding import png
        from django.core.files.uploadedfile import SimpleUploadedFile
        recipient = address.user
        address.refresh_from_db()
        self.assertTrue(address.verified)
        self.assertFalse(complete(recipient))
        self.assertFalse(Membership.objects.filter(user=recipient).exists())
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.assertRedirects(self.client.get(self.url), reverse('onboarding'))
        response = self.client.post(reverse('onboarding'), {
            'signature': SimpleUploadedFile('signature.png', png())})
        self.assertRedirects(response, self.url)
        recipient.refresh_from_db()
        self.assertTrue(complete(recipient))
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)
        self.assertFalse(Membership.objects.filter(user=recipient).exists())
        self.assertContains(self.client.get(self.url), 'Accept invitation')
        self.assertRedirects(self.client.post(self.url), reverse('department_dashboard', args=[self.department.pk]))
        self.invite.refresh_from_db()
        self.assertTrue(self.invite.accepted)
        self.assertEqual(Membership.objects.get(user=recipient, department=self.department).role, 'O')

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
        request.session = {'pending_invite_token': self.invite.token, 'invite_verification_intent': [self.invite.token, self.user.pk]}
        with patch('allauth.account.adapter.DefaultAccountAdapter.post_login') as finish:
            InvitationAccountAdapter().post_login(request, self.user, redirect_url=self.url)
        self.assertEqual(finish.call_args.kwargs['redirect_url'], self.url)

    def test_unrelated_login_destinations(self):
        from .test_fixtures import complete_onboarding
        other = User.objects.create_user(username='other', password='password')
        complete_onboarding(other)
        for username in ('recipient', 'other'):
            for target in (None, '/accounts/waiting-room/'):
                self.client.logout()
                self.client.get(self.url)
                session = self.client.session
                session['invite_verification_intent'] = [self.invite.token, self.user.pk]
                session.save()
                data = {'login': username, 'password': 'password'}
                if target:
                    data['next'] = target
                response = self.client.post(reverse('account_login'), data)
                self.assertEqual(response.url, target or '/accounts/route/')
                self.assertNotIn('invite_verification_intent', self.client.session)
                self.assertEqual(self.client.post(self.url).status_code, 403)
                self.invite.refresh_from_db()
                self.assertFalse(self.invite.accepted)

    def test_existing_recipient_verification(self):
        from allauth.account.models import EmailConfirmationHMAC
        address = EmailAddress.objects.create(user=self.user, email=self.invite.email, verified=False)
        self.client.get(self.url)
        response = self.client.post(reverse('account_login'), {'login': 'recipient', 'password': 'password', 'next': self.url})
        self.assertEqual(response.url, self.url)
        self.client.get(self.url)
        self.invite.refresh_from_db()
        self.assertFalse(self.invite.accepted)
        response = self.client.post(reverse('account_confirm_email', args=[EmailConfirmationHMAC(address).key]))
        self.assertEqual(response.url, self.url)
        self.assertEqual(self.client.post(self.url).status_code, 302)

    def test_stale_context_cleanup(self):
        from .invitations import pending_invitation_url
        tokens = ['', None, 42, [], 'x' * 65, 'unmatched']
        for state in ('expired', 'consumed', 'deleted', 'inactive'):
            invitation = Invitation.objects.create(email='stale@example.com', department=self.department, inviter=self.ap)
            tokens.append(invitation.token)
            if state == 'expired':
                invitation.expires_at = timezone.now() - timedelta(seconds=1)
                invitation.save()
            elif state == 'consumed':
                invitation.accepted = True
                invitation.save()
            elif state == 'deleted':
                invitation.delete()
            else:
                inactive = Department.objects.create(name='Inactive', is_active=False)
                invitation.department = inactive
                invitation.save()
        for token in tokens:
            with self.subTest(token=token):
                request = RequestFactory().get('/')
                request.session = {'pending_invite_token': token, 'unrelated': 'keep'}
                self.assertIsNone(pending_invitation_url(request))
                self.assertEqual(request.session, {'unrelated': 'keep'})

    def test_invalid_link_cleanup(self):
        session = self.client.session
        session['pending_invite_token'] = 'missing'
        session.save()
        self.assertEqual(self.client.get(reverse('accept_invitation', args=['missing'])).status_code, 404)
        self.assertNotIn('pending_invite_token', self.client.session)
        self.client.get(self.url)
        self.client.get(reverse('accept_invitation', args=['missing']))
        self.assertEqual(self.client.session['pending_invite_token'], self.invite.token)

    def test_ordinary_verification(self):
        from .adapter import InvitationAccountAdapter
        from allauth.core.context import request_context
        request = RequestFactory().get('/')
        request.user = self.user
        request.session = {'pending_invite_token': self.invite.token}
        with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.get_email_verification_redirect_url', return_value='/normal/'):
            self.assertEqual(InvitationAccountAdapter(request).get_email_verification_redirect_url(EmailAddress(user=self.user, email=self.invite.email)), '/normal/')

    def test_google_state_roundtrip(self):
        from django.contrib.sessions.backends.db import SessionStore
        from .adapter import InvitationAccountAdapter
        from allauth.socialaccount.providers.google.provider import GoogleProvider
        from allauth.socialaccount.models import SocialLogin, SocialApp
        from allauth.core.context import request_context
        request = RequestFactory().get('/')
        request.session = SessionStore()
        request.session['pending_invite_token'] = self.invite.token
        provider = GoogleProvider(request=request, app=SocialApp(provider='google', client_id='test'))
        for destination in (self.url, '/accounts/waiting-room/', None):
            state_id = provider.stash_redirect_state(request, process='login', next_url=destination)
            from allauth.socialaccount.providers.oauth2.views import OAuth2CallbackView
            from types import SimpleNamespace
            callback = OAuth2CallbackView()
            callback.adapter = SimpleNamespace(supports_state=True)
            request.GET = request.GET.copy()
            request.GET['state'] = state_id
            state, response = callback._get_state(request, provider)
            self.assertIsNone(response)
            sociallogin = SocialLogin()
            sociallogin.state = state
            sociallogin.user = self.user
            from allauth.socialaccount.internal.flows import login as social_login_flow
            with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.post_login') as finish:
                with patch.object(sociallogin, '_accept_login'), patch.object(social_login_flow, 'record_authentication'), patch.object(social_login_flow, 'perform_login', side_effect=lambda req, user, **kw: InvitationAccountAdapter(req).post_login(req, user, **kw)):
                    social_login_flow._login(request, sociallogin)
            self.assertEqual(finish.call_args.kwargs['redirect_url'], destination)
            self.assertEqual('invite_verification_intent' in request.session, destination == self.url)

    def test_authenticated_view_does_not_establish_intent(self):
        self.client.force_login(self.user)
        self.client.get(self.url)
        self.assertNotIn('invite_verification_intent', self.client.session)
        session = self.client.session
        session['invite_verification_intent'] = [self.invite.token, self.user.pk]
        session.save()
        self.client.get(self.url)
        self.assertEqual(self.client.session['invite_verification_intent'], [self.invite.token, self.user.pk])
        self.verify()
        self.client.post(self.url)
        self.assertNotIn('pending_invite_token', self.client.session)
        self.assertNotIn('invite_verification_intent', self.client.session)

    def test_verification_context_validation(self):
        from .adapter import InvitationAccountAdapter
        from allauth.core.context import request_context
        request = RequestFactory().get('/')
        request.user = self.user
        address = EmailAddress(user=self.user, email=self.invite.email)
        cases = [({}, False), ({'pending_invite_token': self.invite.token}, False),
            ({'pending_invite_token': self.invite.token, 'invite_verification_intent': ['changed', self.user.pk]}, False),
            ({'pending_invite_token': self.invite.token, 'invite_verification_intent': [self.invite.token, self.ap.pk]}, False),
            ({'pending_invite_token': self.invite.token, 'invite_verification_intent': [self.invite.token, self.user.pk]}, True)]
        for session, expected in cases:
            with self.subTest(session=session):
                request.session = session.copy()
                with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.get_email_verification_redirect_url', return_value='/normal/'):
                    self.assertEqual(InvitationAccountAdapter(request).get_email_verification_redirect_url(address), self.url if expected else '/normal/')
        for state in ('expired', 'inactive'):
            with self.subTest(state=state):
                request.session = {'pending_invite_token': self.invite.token, 'invite_verification_intent': [self.invite.token, self.user.pk], 'unrelated': 'keep'}
                if state == 'expired':
                    self.invite.expires_at = timezone.now() - timedelta(seconds=1)
                    self.invite.save()
                else:
                    self.invite.expires_at = timezone.now() + timedelta(days=1)
                    self.invite.save()
                    self.department.is_active = False
                    self.department.save()
                with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.get_email_verification_redirect_url', return_value='/normal/'):
                    self.assertEqual(InvitationAccountAdapter(request).get_email_verification_redirect_url(address), '/normal/')
                self.assertEqual(request.session, {'unrelated': 'keep'})

    def test_invalid_and_replacement_invitation_policy(self):
        self.client.get(self.url)
        session = self.client.session
        session['invite_verification_intent'] = [self.invite.token, self.user.pk]
        session['unrelated'] = 'keep'
        session.save()
        expired = Invitation.objects.create(email=self.invite.email, department=self.department, inviter=self.ap,
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get(reverse('accept_invitation', args=[expired.token])).status_code, 400)
        self.assertEqual(self.client.session['pending_invite_token'], self.invite.token)
        self.assertEqual(self.client.session['invite_verification_intent'], [self.invite.token, self.user.pk])
        replacement = Invitation.objects.create(email=self.invite.email, department=self.department, inviter=self.ap)
        self.client.get(reverse('accept_invitation', args=[replacement.token]))
        self.assertEqual(self.client.session['pending_invite_token'], replacement.token)
        self.assertNotIn('invite_verification_intent', self.client.session)
        self.assertEqual(self.client.session['unrelated'], 'keep')

    def test_verification_email_normalization_and_unrelated_address(self):
        from .adapter import InvitationAccountAdapter
        from allauth.core.context import request_context
        self.invite.email = self.invite.email.upper()
        self.invite.save()
        request = RequestFactory().get('/')
        request.user = self.user
        request.session = {'pending_invite_token': self.invite.token,
            'invite_verification_intent': [self.invite.token, self.user.pk]}
        with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.get_email_verification_redirect_url', return_value='/normal/'):
            adapter = InvitationAccountAdapter(request)
            self.assertEqual(adapter.get_email_verification_redirect_url(EmailAddress(user=self.user, email=self.invite.email.lower())), self.url)
            self.assertEqual(adapter.get_email_verification_redirect_url(EmailAddress(user=self.user, email='other@example.com')), '/normal/')

    def test_verification_intent_cannot_cross_authenticated_accounts(self):
        from .adapter import InvitationAccountAdapter
        from allauth.core.context import request_context
        request = RequestFactory().get('/')
        request.user = self.ap
        request.session = {'pending_invite_token': self.invite.token,
            'invite_verification_intent': [self.invite.token, self.user.pk]}
        address = EmailAddress(user=self.user, email=self.invite.email, verified=True)
        with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.get_email_verification_redirect_url', return_value='/normal/') as fallback:
            self.assertEqual(InvitationAccountAdapter(request).get_email_verification_redirect_url(address), '/normal/')
            fallback.assert_called_once_with(address)
