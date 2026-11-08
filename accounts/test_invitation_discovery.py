from datetime import timedelta

from allauth.account.models import EmailAddress
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .invitations import DISCOVERY_LIMIT, recipient_invitations
from .models import Department, Invitation, Membership, User
from .test_fixtures import complete_onboarding, signature_storage
from meetings.models import AuditLog


class InvitationDiscoveryTests(TestCase):
    def setUp(self):
        signature_storage(self)
        self.user = User.objects.create_user(username='recipient', email='untrusted@example.com')
        complete_onboarding(self.user)
        self.admin = User.objects.create_user(username='admin', is_admin=True)
        self.department = Department.objects.create(name='Private department')
        self.url = reverse('central_dashboard')
        self.client.force_login(self.user)

    def invite(self, email='owned@example.com', **kwargs):
        return Invitation.objects.create(email=email, department=self.department, inviter=self.admin, **kwargs)

    def verify(self, email='owned@example.com', **kwargs):
        return EmailAddress.objects.create(user=self.user, email=email, verified=True, **kwargs)

    def test_primary_secondary_case_and_isolation(self):
        self.verify(primary=True)
        self.verify('SECONDARY@example.com')
        EmailAddress.objects.create(user=self.user, email='unverified@example.com', verified=False)
        EmailAddress.objects.create(user=self.admin, email='other@example.com', verified=True)
        primary = self.invite('OWNED@EXAMPLE.COM')
        secondary = self.invite('secondary@EXAMPLE.COM')
        hidden = [self.invite(email) for email in (
            'unverified@example.com', 'other@example.com', self.user.email)]
        response = self.client.get(self.url, {'email': 'other@example.com'})
        self.assertEqual({i.pk for i in response.context['pending_invitations']}, {primary.pk, secondary.pk})
        self.assertContains(response, self.department.name)
        for invitation in hidden:
            self.assertNotContains(response, reverse('accept_invitation', args=[invitation.token]))

    def test_ineligible_session_links_hidden_without_session_changes(self):
        self.verify()
        for state in ('unrelated', 'unverified', 'expired', 'accepted', 'inactive', 'deleted'):
            invitation = self.invite('other@example.com' if state == 'unrelated' else
                                     'unverified@example.com' if state == 'unverified' else 'owned@example.com')
            if state == 'unverified':
                EmailAddress.objects.create(user=self.user, email=invitation.email, verified=False)
            if state == 'expired':
                Invitation.objects.filter(pk=invitation.pk).update(expires_at=timezone.now()-timedelta(seconds=1))
            if state == 'accepted':
                Invitation.objects.filter(pk=invitation.pk).update(accepted=True)
            if state == 'inactive':
                Department.objects.filter(pk=self.department.pk).update(is_active=False)
            if state == 'deleted':
                invitation.delete()
            session = self.client.session
            session['pending_invite_token'] = invitation.token
            session['invite_verification_intent'] = [invitation.token, self.user.pk]
            session.save()
            before = dict(self.client.session)
            with self.subTest(state=state):
                response = self.client.get(self.url)
                self.assertNotContains(response, reverse('accept_invitation', args=[invitation.token]))
                self.assertEqual(dict(self.client.session), before)
            Department.objects.filter(pk=self.department.pk).update(is_active=True)

    def test_session_discovery_not_duplicated(self):
        self.verify()
        invitation = self.invite()
        session = self.client.session; session['pending_invite_token'] = invitation.token; session.save()
        response = self.client.get(self.url)
        self.assertContains(response, reverse('accept_invitation', args=[invitation.token]), count=1)
        self.assertContains(response, '<li class="invitation-card">', count=1)

    def test_cards_have_headings_expiry_and_named_review_links(self):
        from django.template.defaultfilters import date
        self.verify()
        first = self.invite()
        second_department = Department.objects.create(name='Second department')
        second = Invitation.objects.create(email=first.email, department=second_department,
                                           inviter=self.admin)
        session = self.client.session; session['pending_invite_token'] = first.token; session.save()
        response = self.client.get(self.url)
        html = response.content.decode()
        self.assertContains(response, '<ul class="invitation-list" role="list">', count=1)
        self.assertContains(response, '<li class="invitation-card">', count=2)
        for invitation in (first, second):
            with self.subTest(department=invitation.department.name):
                self.assertInHTML(f'<h3>{invitation.department.name}</h3>', html)
                expiry = date(timezone.localtime(invitation.expires_at), 'c')
                self.assertInHTML(f'<p>Expires <time datetime="{expiry}">{expiry}</time></p>', html)
                url = reverse('accept_invitation', args=[invitation.token])
                self.assertContains(response, url, count=1)
                self.assertInHTML(
                    f'<a class="invitation-card__review" href="{url}" '
                    f'aria-label="Review invitation to {invitation.department.name}">Review invitation</a>', html)
        self.assertNotContains(response, '<form')
        self.assertNotContains(response, first.email)

    def test_card_department_name_is_escaped_in_heading_and_accessible_name(self):
        from django.utils.html import escape
        self.verify()
        name = '<script>alert("x")</script> & "Team"'
        self.department.name = name
        self.department.save()
        invitation = self.invite()
        response = self.client.get(self.url)
        self.assertNotContains(response, name)
        self.assertNotContains(response, '<script>')
        self.assertInHTML(f'<h3>{escape(name)}</h3>', response.content.decode())
        self.assertContains(response, f'aria-label="Review invitation to {escape(name)}"', count=1)
        self.assertContains(response, reverse('accept_invitation', args=[invitation.token]), count=1)

    def test_card_empty_state_preserves_dashboard_navigation(self):
        self.verify()
        response = self.client.get(self.url)
        self.assertNotContains(response, '<li class="invitation-card">')
        self.assertNotContains(response, '<h2 id="invitation-heading">')
        self.assertContains(response, "To accept an invitation, open the link provided by your department's Authorized Personnel.")
        self.assertContains(response, reverse('create_department'))
        self.assertContains(response, 'You have no active departments.')

    def test_deterministic_bound_and_eligible_overflow_continuation(self):
        self.verify()
        invitations = [self.invite() for _ in range(DISCOVERY_LIMIT + 5)]
        Invitation.objects.all().update(created_at=timezone.now())
        expected = [i.pk for i in reversed(invitations[-DISCOVERY_LIMIT:])]
        self.assertEqual([i.pk for i in recipient_invitations(self.user)], expected)
        session = self.client.session; session['pending_invite_token'] = invitations[0].token; session.save()
        result = self.client.get(self.url).context['pending_invitations']
        self.assertEqual([i.pk for i in result], expected + [invitations[0].pk])
        self.assertEqual(len({i.pk for i in result}), DISCOVERY_LIMIT + 1)

    def test_get_no_mutations_and_acceptance_remains_explicit(self):
        self.verify()
        invitation = self.invite()
        before = (list(Invitation.objects.values()), list(Membership.objects.values()),
                  list(EmailAddress.objects.values()), list(AuditLog.objects.values()))
        self.client.get(self.url)
        self.assertEqual(before, (list(Invitation.objects.values()), list(Membership.objects.values()),
                         list(EmailAddress.objects.values()), list(AuditLog.objects.values())))
        target = reverse('accept_invitation', args=[invitation.token])
        self.assertContains(self.client.get(target), 'Accept invitation')
        self.assertFalse(Membership.objects.filter(user=self.user).exists())
        self.assertEqual(self.client.post(target).status_code, 302)
        self.assertTrue(Membership.objects.filter(user=self.user, department=self.department).exists())

    def test_replacement_uses_existing_revocation_semantics(self):
        self.verify()
        old = self.invite()
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(reverse('invite_member', args=[self.department.pk]),
            {'email': old.email, 'role': 'O'}).status_code, 302)
        self.assertFalse(Invitation.objects.filter(pk=old.pk).exists())
        replacement = Invitation.objects.get(email=old.email)
        self.client.force_login(self.user)
        session = self.client.session; session['pending_invite_token'] = old.token; session.save()
        response = self.client.get(self.url)
        self.assertNotContains(response, reverse('accept_invitation', args=[old.token]))
        self.assertContains(response, reverse('accept_invitation', args=[replacement.token]), count=1)
        self.assertEqual(self.client.session['pending_invite_token'], old.token)

    def test_anonymous_inactive_and_admin_routing(self):
        self.assertFalse(recipient_invitations(AnonymousUser()).exists())
        self.user.is_active = False
        self.assertFalse(recipient_invitations(self.user).exists())
        self.client.force_login(self.admin)
        self.assertRedirects(self.client.get(self.url), reverse('admin_dashboard'))


class InvitationFragmentTests(TestCase):
    """Run discovery/card contracts against the same partial and test the polling boundary."""
    setUp = InvitationDiscoveryTests.setUp
    invite = InvitationDiscoveryTests.invite
    verify = InvitationDiscoveryTests.verify
    def marker(self):
        return self.client.get(reverse('central_dashboard')).context['invitation_page_marker']

    def fragment(self, marker=None, **query):
        return self.client.get(reverse('invitation_fragment'), query,
                               HTTP_X_INVITATION_PAGE=marker or self.marker())

    def test_fragment_matches_initial_markup_and_does_not_mutate_state(self):
        from django.template.loader import render_to_string
        self.verify()
        invitation = self.invite()
        session = self.client.session
        session['pending_invite_token'] = invitation.token
        session['invite_verification_intent'] = [invitation.token, self.user.pk]
        session.save()
        page = self.client.get(self.url)
        marker = page.context['invitation_page_marker']
        expected = render_to_string('accounts/_invitation_cards.html', {
            'pending_invitations': page.context['pending_invitations']})
        before = (list(Invitation.objects.values()), list(Membership.objects.values()),
                  list(EmailAddress.objects.values()), list(User.objects.values()),
                  list(AuditLog.objects.values()), dict(self.client.session))
        response = self.fragment(marker)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), expected)
        self.assertContains(page, expected)
        self.assertEqual(response['X-VeriMeet-Fragment'], 'invitations')
        self.assertIn('private', response['Cache-Control'])
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(before, (list(Invitation.objects.values()), list(Membership.objects.values()),
                         list(EmailAddress.objects.values()), list(User.objects.values()),
                         list(AuditLog.objects.values()), dict(self.client.session)))

    def test_missing_invalid_and_cross_account_markers(self):
        self.verify(); invitation = self.invite()
        marker = self.marker()
        endpoint = reverse('invitation_fragment')
        for supplied in ('', 'invalid', marker + 'tamper', 'x' * 513):
            response = self.client.get(endpoint, HTTP_X_INVITATION_PAGE=supplied)
            self.assertEqual(response.status_code, 403)
            self.assertNotContains(response, invitation.token, status_code=403)
        other = User.objects.create_user(username='other-recipient')
        complete_onboarding(other)
        self.client.force_login(other)
        self.assertEqual(self.fragment(marker).status_code, 403)

    def test_fragment_rechecks_account_changes_after_authentication_loaded_user(self):
        from django.test import RequestFactory
        from django.db import transaction
        from .views import invitation_fragment
        from .account_status import change_account_status
        self.verify()
        invitation = self.invite()
        marker = self.marker()
        for state in ('admin', 'superuser', 'incomplete', 'inactive', 'reactivated', 'password'):
            with self.subTest(state=state), transaction.atomic():
                request = RequestFactory().get(reverse('invitation_fragment'), HTTP_X_INVITATION_PAGE=marker)
                request.user = User.objects.get(pk=self.user.pk)
                request.session = self.client.session
                if state in ('inactive', 'reactivated'):
                    change_account_status(self.admin, self.user.pk, False)
                    if state == 'reactivated':
                        change_account_status(self.admin, self.user.pk, True)
                else:
                    field, value = {
                        'admin': ('is_admin', True), 'superuser': ('is_superuser', True),
                        'incomplete': ('username_confirmation_required', True),
                        'password': ('password', 'changed-authentication-hash'),
                    }[state]
                    User.objects.filter(pk=self.user.pk).update(**{field: value})
                response = invitation_fragment(request)
                self.assertEqual(response.status_code, 403)
                self.assertNotContains(response, invitation.token, status_code=403)
                self.assertNotIn('X-VeriMeet-Fragment', response)
                self.assertIn('no-store', response['Cache-Control'])
                transaction.set_rollback(True)

    def test_login_session_and_account_version_invalidate_marker(self):
        marker = self.marker()
        session = self.client.session; session.cycle_key(); session.save()
        from django.conf import settings
        self.client.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
        self.assertEqual(self.fragment(marker).status_code, 403)
        marker = self.marker()
        self.client.logout(); self.client.force_login(self.user)
        self.assertEqual(self.fragment(marker).status_code, 403)
        marker = self.marker()
        from .account_status import change_account_status
        change_account_status(self.admin, self.user.pk, False)
        self.assertEqual(self.fragment(marker).status_code, 302)
        change_account_status(self.admin, self.user.pk, True)
        self.user.refresh_from_db(); self.client.force_login(self.user)
        self.assertEqual(self.fragment(marker).status_code, 403)

    def test_fragment_access_and_methods(self):
        marker = self.marker()
        endpoint = reverse('invitation_fragment')
        for method in ('post', 'put', 'patch', 'delete', 'head', 'options'):
            response = getattr(self.client, method)(endpoint, HTTP_X_INVITATION_PAGE=marker)
            self.assertEqual(response.status_code, 405)
        self.client.logout()
        self.assertEqual(self.fragment(marker).status_code, 302)
        incomplete = User.objects.create_user(username='incomplete')
        self.client.force_login(incomplete)
        self.assertRedirects(self.fragment(marker), reverse('onboarding'))
        self.client.force_login(self.admin)
        self.assertEqual(self.fragment(marker).status_code, 403)
        self.assertRedirects(self.client.get(self.url), reverse('admin_dashboard'))

    def test_fragment_filters_and_empty_transitions(self):
        self.verify(primary=True)
        self.verify('secondary@example.com')
        EmailAddress.objects.create(user=self.user, email='unverified@example.com', verified=False)
        marker = self.marker()
        self.assertNotContains(self.fragment(marker), '<li class="invitation-card">')
        valid = self.invite('SECONDARY@EXAMPLE.COM')
        hidden = [self.invite('unverified@example.com'), self.invite('other@example.com'),
                  self.invite(expires_at=timezone.now()-timedelta(seconds=1)), self.invite(accepted=True)]
        response = self.fragment(marker, email='other@example.com', department=self.department.pk)
        self.assertContains(response, reverse('accept_invitation', args=[valid.token]), count=1)
        for invitation in hidden:
            self.assertNotContains(response, invitation.token)
        self.assertNotContains(response, valid.email)
        Invitation.objects.filter(pk=valid.pk).update(accepted=True)
        self.assertNotContains(self.fragment(marker), '<li class="invitation-card">')
        Invitation.objects.filter(pk=valid.pk).update(accepted=False)
        Department.objects.filter(pk=self.department.pk).update(is_active=False)
        self.assertNotContains(self.fragment(marker), '<li class="invitation-card">')

    def test_fragment_limit_continuation_replacement_and_escaping(self):
        self.verify()
        self.department.name = '<em>Private & "team"</em>'; self.department.save()
        invitations = [self.invite() for _ in range(DISCOVERY_LIMIT + 2)]
        continuation = invitations[0]
        session = self.client.session; session['pending_invite_token'] = continuation.token; session.save()
        marker = self.marker()
        response = self.fragment(marker)
        self.assertContains(response, '<li class="invitation-card">', count=DISCOVERY_LIMIT + 1)
        self.assertContains(response, reverse('accept_invitation', args=[continuation.token]), count=1)
        self.assertNotContains(response, '<em>')
        continuation.delete()  # Replacement revokes the former token by deleting its row.
        response = self.fragment(marker)
        self.assertNotContains(response, continuation.token)
        self.assertEqual(self.client.session['pending_invite_token'], continuation.token)
