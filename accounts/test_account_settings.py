from tempfile import TemporaryDirectory
from unittest.mock import patch
from django.core.files.base import ContentFile
from django.db import IntegrityError, OperationalError
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from meetings.models import AuditLog
from .models import User, Department, Membership, Invitation
from .signatures import signature_valid
from .test_onboarding import png


class AccountSettingsTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
        setting.enable(); self.addCleanup(setting.disable)
        self.user = User.objects.create_user(username='officer', password='password123')
        self.user.signature_image.save('signature.png', ContentFile(png()))
        self.assertTrue(signature_valid(self.user))
        self.admin = User.objects.create_user(username='global', is_admin=True)
        self.a = Department.objects.create(name='Alpha')
        self.b = Department.objects.create(name='Beta')
        Membership.objects.create(user=self.user, department=self.a, role='O')
        Membership.objects.create(user=self.user, department=self.b, role='AP')
        self.url = reverse('account_settings')
        self.client.force_login(self.user)

    def test_roles_and_onboarding(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Officer')
        self.assertContains(response, 'Authorized Personnel')
        self.assertContains(response, reverse('central_dashboard'))
        self.client.force_login(self.admin)
        response = self.client.get(self.url)
        self.assertContains(response, 'No valid signature')
        self.assertContains(response, reverse('admin_dashboard'))
        incomplete = User.objects.create_user(username='incomplete')
        self.client.force_login(incomplete)
        self.assertRedirects(self.client.get(self.url), reverse('onboarding'))
        self.assertEqual(self.client.post(self.url, {'username': 'bypass'}).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)

    def test_username_change_and_audit_preserve_other_fields(self):
        before = User.objects.values().get(pk=self.user.pk)
        memberships = list(Membership.objects.values())
        response = self.client.post(self.url + '?user_id=' + str(self.admin.pk), {
            'username': 'selected', 'user_id': self.admin.pk, 'is_admin': 'True',
            'is_staff': 'True', 'is_superuser': 'True', 'is_active': '', 'department': self.b.pk,
            'email': 'intruder@example.com', 'first_name': 'Changed', 'last_name': 'Changed',
            'private_key': 'changed', 'signature_validated': '', 'signature_validation_hash': 'changed',
        })
        self.assertRedirects(response, self.url)
        after = User.objects.values().get(pk=self.user.pk)
        self.assertEqual(after.pop('username'), 'selected')
        before.pop('username')
        self.assertEqual(before, after)
        self.assertEqual(memberships, list(Membership.objects.values()))
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.username, 'global')
        event = AuditLog.objects.get(event_type='user.username_changed')
        self.assertEqual(event.user_id, self.user.pk)
        self.assertEqual(event.target_id, str(self.user.pk))
        self.assertNotIn('private_key', event.metadata)

    def test_username_validation_and_noop(self):
        for username in ('bad name', 'global', 'GLOBAL', ''):
            response = self.client.post(self.url, {'username': username})
            self.assertEqual(response.status_code, 200)
            self.assertIn('username', response.context['form'].errors)
        self.assertRedirects(self.client.post(self.url, {'username': 'officer'}), self.url)
        self.assertFalse(AuditLog.objects.filter(event_type='user.username_changed').exists())

    def test_concurrent_database_collision(self):
        with patch('accounts.views.User.save', side_effect=IntegrityError):
            response = self.client.post(self.url, {'username': 'claimed'})
        self.assertContains(response, 'no longer available')
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'officer')
        self.assertFalse(AuditLog.objects.filter(event_type='user.username_changed').exists())

    def test_audit_failure_rolls_back_username(self):
        with patch('accounts.views.record', side_effect=IntegrityError):
            self.assertEqual(self.client.post(self.url, {'username': 'rollback'}).status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'officer')

    def test_concurrent_database_lock_is_retryable(self):
        for message in ('database is locked', 'database is busy',
                        'database table is locked: accounts_user', 'database schema is locked: main'):
            with self.subTest(message=message), patch('accounts.views.record', side_effect=OperationalError(message)):
                response = self.client.post(self.url, {'username': 'retry'})
            self.assertContains(response, 'Please retry')
            self.user.refresh_from_db()
            self.assertEqual(self.user.username, 'officer')
            self.assertFalse(AuditLog.objects.filter(event_type='user.username_changed').exists())

    def test_unrelated_operational_error_is_not_swallowed(self):
        with patch('accounts.views.record', side_effect=OperationalError('disk I/O error')):
            with self.assertRaisesMessage(OperationalError, 'disk I/O error'):
                self.client.post(self.url, {'username': 'rollback'})
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'officer')
        self.assertFalse(AuditLog.objects.filter(event_type='user.username_changed').exists())

    def test_sqlite_extended_busy_code_is_retryable(self):
        from sqlite3 import OperationalError as SQLiteError, SQLITE_BUSY
        cause = SQLiteError('busy snapshot')
        cause.sqlite_errorcode = SQLITE_BUSY | (2 << 8)
        error = OperationalError('busy snapshot')
        error.__cause__ = cause
        with patch('accounts.views.record', side_effect=error):
            response = self.client.post(self.url, {'username': 'retry'})
        self.assertContains(response, 'Please retry')
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'officer')

    def test_email_and_password_links(self):
        EmailAddress.objects.create(user=self.user, email='primary@example.com', primary=True, verified=True)
        EmailAddress.objects.create(user=self.user, email='secondary@example.com', verified=False)
        SocialAccount.objects.create(user=self.user, provider='google', uid='example')
        response = self.client.get(self.url)
        for value in ('primary@example.com', 'secondary@example.com', 'Verified', 'Unverified',
                      reverse('account_email'), reverse('account_change_password')):
            self.assertContains(response, value)
        self.assertNotContains(response, reverse('account_set_password'))
        self.user.set_unusable_password(); self.user.save(update_fields=['password'])
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertContains(response, reverse('account_set_password'))
        self.assertNotContains(response, reverse('account_change_password'))

    def test_membership_filter_and_preview_privacy(self):
        inactive = Department.objects.create(name='Inactive', is_active=False)
        Membership.objects.create(user=self.user, department=inactive)
        Department.objects.create(name='Unjoined')
        response = self.client.get(self.url)
        self.assertNotContains(response, 'Inactive')
        self.assertNotContains(response, 'Unjoined')
        self.assertContains(response, reverse('signature_preview'))
        self.assertNotContains(response, self.user.signature_image.name)
        self.assertContains(response, reverse('replace_account_signature'))
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 200)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 404)

    def test_dashboard_navigation_and_logout_confirmation(self):
        for url in (reverse('central_dashboard'), self.url,
                    reverse('department_dashboard', args=[self.a.pk]),
                    reverse('department_dashboard', args=[self.b.pk])):
            response = self.client.get(url)
            self.assertContains(response, self.url)
            self.assertContains(response, reverse('account_logout'))
        self.assertContains(self.client.get(reverse('account_logout')), 'method="post"')
        self.assertIn('_auth_user_id', self.client.session)
        self.client.post(reverse('account_logout'))
        self.assertNotIn('_auth_user_id', self.client.session)
        self.client.force_login(self.admin)
        for url in (reverse('admin_dashboard'), reverse('department_dashboard', args=[self.a.pk])):
            response = self.client.get(url)
            self.assertContains(response, self.url)
            self.assertContains(response, reverse('account_logout'))
        self.assertContains(self.client.get(reverse('account_logout')), 'method="post"')

    def test_csrf_and_invitation_session_preserved(self):
        client = Client(enforce_csrf_checks=True); client.force_login(self.user)
        self.assertEqual(client.post(self.url, {'username': 'forged'}).status_code, 403)
        invitation = Invitation.objects.create(department=self.a, inviter=self.admin, email='owned@example.com')
        session = self.client.session
        context = {'pending_invite_token': invitation.token,
                   'invite_verification_intent': [invitation.token, self.user.pk],
                   'onboarding_invitation': [invitation.token, self.user.pk]}
        session.update(context); session.save()
        self.client.get(self.url)
        self.client.post(self.url, {'username': 'renamed'})
        for key, value in context.items():
            self.assertEqual(self.client.session[key], value)
