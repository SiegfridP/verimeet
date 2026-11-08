from types import SimpleNamespace
from unittest.mock import patch
from django.test import TestCase, Client, RequestFactory
from django.urls import reverse
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, OperationalError
from django.contrib import admin
from allauth.account.adapter import DefaultAccountAdapter
from meetings.models import AuditLog
from .models import User, Department, Membership, Invitation
from .account_status import change_account_status


class AccountStatusTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username='global', is_admin=True)
        self.target = User.objects.create_user(username='target', password='test-password')

    def test_transition_noop_and_data_preservation(self):
        dept = Department.objects.create(name='Status')
        Membership.objects.create(user=self.target, department=dept, role='AP')
        invitation = Invitation.objects.create(inviter=self.target, department=dept, email='test@example.com')
        before = User.objects.values().get(pk=self.target.pk)
        self.assertTrue(change_account_status(self.actor, self.target.pk, False))
        self.assertFalse(change_account_status(self.actor, self.target.pk, False))
        self.assertTrue(change_account_status(self.actor, self.target.pk, True))
        after = User.objects.values().get(pk=self.target.pk)
        self.assertEqual(after.pop('session_version'), 1)
        before.pop('session_version')
        self.assertEqual(before, after)
        self.assertEqual(Membership.objects.get(user=self.target).role, 'AP')
        self.assertTrue(Invitation.objects.filter(pk=invitation.pk).exists())
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 2)

    def test_authorization_and_fresh_state(self):
        from django.contrib.auth.models import AnonymousUser
        for actor in (AnonymousUser(), self.target, User.objects.create_user(username='staff', is_staff=True),
                      User.objects.create_user(username='inactive', is_admin=True, is_active=False)):
            with self.assertRaises(PermissionDenied):
                change_account_status(actor, self.target.pk, False)
        for target in (self.actor, User.objects.create_user(username='super', is_superuser=True)):
            with self.assertRaises(PermissionDenied):
                change_account_status(self.actor, target.pk, False)
        stale = User.objects.get(pk=self.actor.pk)
        User.objects.filter(pk=self.actor.pk).update(is_admin=False)
        with self.assertRaises(PermissionDenied):
            change_account_status(stale, self.target.pk, False)

    def test_stale_transition_and_promoted_target(self):
        change_account_status(self.actor, self.target.pk, False)
        change_account_status(self.actor, self.target.pk, True)
        with self.assertRaises(ValidationError):
            change_account_status(self.actor, self.target.pk, False, True, 0)
        User.objects.filter(pk=self.target.pk).update(is_superuser=True)
        with self.assertRaises(PermissionDenied):
            change_account_status(self.actor, self.target.pk, False)

    def test_audit_rollback(self):
        with patch('accounts.account_status.record', side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                change_account_status(self.actor, self.target.pk, False)
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.session_version, 0)

    def test_multiple_sessions_never_return_and_new_login_works(self):
        clients = [Client(), Client()]
        for client in clients:
            self.assertTrue(client.login(username='target', password='test-password'))
        keys = [client.session.session_key for client in clients]
        stale_login_user = User.objects.get(pk=self.target.pk)
        change_account_status(self.actor, self.target.pk, False)
        self.assertFalse(Client().login(username='target', password='test-password'))
        self.assertEqual(clients[0].get(reverse('routing_view')).status_code, 302)
        change_account_status(self.actor, self.target.pk, True)
        for key in keys:
            restored = Client(); restored.cookies['sessionid'] = key
            self.assertEqual(restored.get(reverse('account_settings')).status_code, 302)
            self.assertNotIn('_auth_user_id', restored.session)
        late = Client(); late.force_login(stale_login_user)
        self.assertEqual(late.get(reverse('account_settings')).status_code, 302)
        self.assertNotIn('_auth_user_id', late.session)
        self.assertTrue(Client().login(username='target', password='test-password'))

    def test_stale_model_save_cannot_restore_revocation_version(self):
        stale = User.objects.get(pk=self.target.pk)
        change_account_status(self.actor, self.target.pk, False)
        stale.first_name = 'Preserved'
        stale.save()
        self.target.refresh_from_db()
        self.assertEqual(self.target.session_version, 1)
        self.assertFalse(self.target.is_active)
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 1)

    def test_google_existing_login_rejects_inactive(self):
        from allauth.socialaccount.models import SocialLogin, SocialAccount
        from allauth.socialaccount.internal.flows.login import _login
        from allauth.core.context import request_context
        change_account_status(self.actor, self.target.pk, False)
        self.target.refresh_from_db()
        request = RequestFactory().get('/')
        request.user = self.target
        request.session = {}
        social = SocialLogin(user=self.target, account=SocialAccount(provider='google', uid='example'))
        social._did_authenticate_by_email = False  # Normally initialized by provider lookup.
        with request_context(request), patch('allauth.account.adapter.DefaultAccountAdapter.respond_user_inactive') as inactive:
            _login(request, social)
        inactive.assert_called_once()

    def test_ui_confirmation_csrf_and_directory(self):
        self.client.force_login(self.actor)
        url = reverse('account_status_confirmation', args=[self.target.pk])
        response = self.client.get(url)
        self.target.refresh_from_db(); self.assertTrue(self.target.is_active)
        self.assertEqual(self.client.post(url, {}).status_code, 400)
        client = Client(enforce_csrf_checks=True); client.force_login(self.actor)
        self.assertEqual(client.post(url, {}).status_code, 403)
        self.assertRedirects(self.client.post(url, {'state': response.context['state'], 'confirm': 'on', 'is_superuser': 'on'}), reverse('account_directory'))
        self.target.refresh_from_db(); self.assertFalse(self.target.is_active)
        self.assertFalse(self.target.is_superuser)
        self.assertContains(self.client.get(reverse('account_directory')), 'Protected Global Admin')

    def admin_save(self, actor, target, fields):
        request = RequestFactory().post('/admin/'); request.user = actor
        current = User.objects.get(pk=target.pk)
        form = SimpleNamespace(changed_data=fields, cleaned_data={'confirm_account_status': True},
            security_initial={field: getattr(current, field) for field in
                ('is_admin', 'is_superuser', 'is_staff', 'is_active', 'session_version')})
        admin.site._registry[User].save_model(request, target, form, True)

    def test_admin_combined_edit_and_revocation(self):
        client = Client(); client.force_login(self.target)
        self.target.is_active = False; self.target.first_name = 'Changed'
        self.admin_save(self.actor, self.target, ['is_active', 'first_name'])
        self.target.refresh_from_db()
        self.assertEqual(self.target.first_name, 'Changed')
        self.assertEqual(self.target.session_version, 1)
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 1)
        self.assertEqual(client.get(reverse('account_settings')).status_code, 302)

    def test_admin_rejects_combined_privilege_bypass_and_staff_actor(self):
        self.target.is_active = False; self.target.is_admin = True
        with self.assertRaises(PermissionDenied):
            self.admin_save(self.actor, self.target, ['is_active', 'is_admin'])
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        staff = User.objects.create_user(username='staff-admin', is_staff=True)
        self.target.is_active = False
        with self.assertRaises(PermissionDenied):
            self.admin_save(staff, self.target, ['is_active'])

    def test_admin_audit_failure_rolls_back_combined_changes(self):
        self.target.is_active = False; self.target.first_name = 'Rollback'
        with patch('accounts.account_status.record', side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                self.admin_save(self.actor, self.target, ['is_active', 'first_name'])
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.session_version, 0)
        self.assertEqual(self.target.first_name, '')

    def test_directory_and_mutation_reject_non_admin(self):
        for user in (self.target, User.objects.create_user(username='staff-ui', is_staff=True)):
            self.client.force_login(user)
            with patch('accounts.signatures.signature_valid', return_value=True):
                self.assertEqual(self.client.get(reverse('account_directory')).status_code, 403)
                self.assertEqual(self.client.post(reverse('account_status_confirmation', args=[self.actor.pk])).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse('account_directory')).status_code, 302)

    def test_contention_safe_and_unrelated_errors_propagate(self):
        self.client.force_login(self.actor)
        url = reverse('account_status_confirmation', args=[self.target.pk])
        state = self.client.get(url).context['state']
        with patch('accounts.account_control_views.change_account_status', side_effect=OperationalError('database is locked')):
            self.assertContains(self.client.post(url, {'state': state, 'confirm': 'on'}), 'Account is busy', status_code=400)
        with patch('accounts.account_control_views.change_account_status', side_effect=OperationalError('disk I/O error')):
            with self.assertRaises(OperationalError):
                self.client.post(url, {'state': state, 'confirm': 'on'})

    def test_ordinary_activity_writes_cannot_bypass_service(self):
        stale = User.objects.get(pk=self.target.pk)
        change_account_status(self.actor, self.target.pk, False)
        stale.is_active = True
        stale.save(update_fields=['is_active'])
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_active)
        self.assertEqual(self.target.session_version, 1)
        with self.assertRaises(PermissionDenied):
            User.objects.filter(pk=self.target.pk).update(is_active=True)
        with self.assertRaises(PermissionDenied):
            User.objects.bulk_update([stale], ['is_active'])
        with self.assertRaises(PermissionDenied):
            User.objects.bulk_create([stale], update_conflicts=True,
                                    update_fields=['is_active'], unique_fields=['username'])
        initial = User.objects.create_user(username='initial-inactive', is_active=False)
        self.assertFalse(User.objects.get(pk=initial.pk).is_active)
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 1)

    def privilege_form(self, proposed=None):
        from django.forms import modelform_factory
        from .admin import SignatureUserChangeForm
        Form = modelform_factory(User, form=SignatureUserChangeForm,
                                fields=['username', 'is_admin', 'is_superuser', 'is_staff'])
        instance = User.objects.get(pk=self.target.pk)
        token = Form(instance=instance).fields['security_state'].initial
        data = {'username': instance.username, 'security_state': token,
                **{field: getattr(instance, field) for field in ('is_admin', 'is_superuser', 'is_staff')}}
        data.update(proposed or {})
        form = Form(data, instance=instance)
        self.assertTrue(form.is_valid(), form.errors)
        return form

    def save_privilege_form(self, form):
        request = RequestFactory().post('/admin/'); request.user = self.actor
        admin.site._registry[User].save_model(request, form.instance, form, True)

    def test_stale_admin_unrelated_edits_preserve_fresh_security_flags(self):
        for field in ('is_admin', 'is_superuser', 'is_staff'):
            User.objects.filter(pk=self.target.pk).update(**{field: False})
            form = self.privilege_form({'username': 'edited-' + field})
            User.objects.filter(pk=self.target.pk).update(**{field: True})
            self.save_privilege_form(form)
            self.target.refresh_from_db()
            self.assertTrue(getattr(self.target, field))
            self.assertEqual(self.target.username, 'edited-' + field)
            User.objects.filter(pk=self.target.pk).update(**{field: False})
        self.assertFalse(AuditLog.objects.filter(event_type='user.role_changed').exists())

    def test_explicit_stale_privilege_change_rejected(self):
        for field in ('is_admin', 'is_superuser', 'is_staff'):
            form = self.privilege_form({field: True, 'username': 'must-not-save'})
            User.objects.filter(pk=self.target.pk).update(**{field: True})
            with self.assertRaises(PermissionDenied):
                self.save_privilege_form(form)
            self.target.refresh_from_db()
            self.assertEqual(self.target.username, 'target')
            User.objects.filter(pk=self.target.pk).update(**{field: False})

    def test_admin_post_reloaded_after_get_uses_signed_original_flags(self):
        from django.forms import modelform_factory
        from .admin import SignatureUserChangeForm
        Form = modelform_factory(User, form=SignatureUserChangeForm,
                                fields=['username', 'is_admin', 'is_superuser', 'is_staff'])
        token = Form(instance=self.target).fields['security_state'].initial
        User.objects.filter(pk=self.target.pk).update(is_admin=True)
        form = Form({'username': 'unrelated-edit', 'security_state': token},
                    instance=User.objects.get(pk=self.target.pk))
        self.assertTrue(form.is_valid(), form.errors)
        self.assertNotIn('is_admin', form.changed_data)
        self.save_privilege_form(form)
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_admin)
        self.assertEqual(self.target.username, 'unrelated-edit')
        invalid = Form({'username': 'forged', 'is_admin': False, 'security_state': 'invalid'},
                       instance=self.target)
        self.assertFalse(invalid.is_valid())
        self.assertIn('security_state', invalid.errors)

    def test_explicit_fresh_privilege_edit_audited_and_atomic(self):
        form = self.privilege_form({'is_admin': True})
        with patch('accounts.admin.record', side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                self.save_privilege_form(form)
        self.target.refresh_from_db(); self.assertFalse(self.target.is_admin)
        self.save_privilege_form(form)
        event = AuditLog.objects.get(event_type='user.role_changed')
        self.assertEqual(event.user_id, self.actor.pk)
        self.assertEqual(event.metadata['new_role'], 'Global Admin')

    def test_strict_stale_replayed_expired_and_noop_confirmations(self):
        self.client.force_login(self.actor)
        url = reverse('account_status_confirmation', args=[self.target.pk])
        state = self.client.get(url).context['state']
        self.assertEqual(self.client.post(url, {'state': state, 'confirm': 'on'}).status_code, 302)
        self.assertEqual(self.client.post(url, {'state': state, 'confirm': 'on'}).status_code, 400)
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 1)
        self.target.refresh_from_db()
        self.assertFalse(change_account_status(self.actor, self.target.pk, False, False, 1))
        with self.assertRaises(ValidationError):
            change_account_status(self.actor, self.target.pk, False, True, 0)
        from django.core import signing
        with patch('django.core.signing.time.time', return_value=1):
            expired = signing.dumps([self.actor.pk, self.target.pk, False, 1], salt='account-status')
        self.assertEqual(self.client.post(url, {'state': expired, 'confirm': 'on'}).status_code, 400)
        self.target.refresh_from_db(); self.assertEqual(self.target.session_version, 1)
        self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), 1)


    def test_malformed_signed_status_payloads_are_rejected_without_mutation(self):
        from django.core import signing
        self.client.force_login(self.actor)
        url = reverse('account_status_confirmation', args=[self.target.pk])
        valid = [self.actor.pk, self.target.pk, True, 0]
        malformed = [None, False, 1, 1.5, 'text', {}, {'state': valid}, [],
                     valid[:3], valid + [None], [[], {}, [], {}]]
        for position, values in enumerate((
                [True, False, str(self.actor.pk), float(self.actor.pk), None, []],
                [True, False, str(self.target.pk), float(self.target.pk), None, {}],
                [0, 1, 'true', 'false', None, []],
                [True, False, -1, 0.0, '0', None, []])):
            for value in values:
                payload = valid.copy()
                payload[position] = value
                malformed.append(payload)
        # Structurally valid tokens must still be bound to actor and target.
        malformed.extend([[self.actor.pk + 100, self.target.pk, True, 0],
                          [self.actor.pk, self.target.pk + 100, True, 0]])
        before = (self.target.is_active, self.target.session_version)
        audit_count = AuditLog.objects.filter(event_type='user.activation_changed').count()
        with patch('accounts.account_control_views.change_account_status') as mutate:
            for index, payload in enumerate(malformed):
                with self.subTest(case=index):
                    response = self.client.post(url, {'confirm': 'on', 'state': signing.dumps(payload, salt='account-status')})
                    self.assertContains(response, 'Account changed or confirmation missing.', status_code=400)
                    self.target.refresh_from_db()
                    self.assertEqual((self.target.is_active, self.target.session_version), before)
                    self.assertEqual(AuditLog.objects.filter(event_type='user.activation_changed').count(), audit_count)
            mutate.assert_not_called()


class AdminActivitySnapshotTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username='snapshot-admin', is_admin=True,
                                             is_staff=True, is_superuser=True)
        self.target = User.objects.create_user(username='snapshot-target')
        self.client.force_login(self.actor)
        self.url = reverse('admin:accounts_user_change', args=[self.target.pk])

    def opened_form_data(self):
        from django import forms
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        form = response.context['adminform'].form
        data = {}
        for name, field in form.fields.items():
            value = form[name].value()
            if isinstance(field, forms.BooleanField):
                if value:
                    data[name] = 'on'
            elif isinstance(field, forms.SplitDateTimeField):
                data[name + '_0'] = value.strftime('%Y-%m-%d') if value else ''
                data[name + '_1'] = value.strftime('%H:%M:%S') if value else ''
            elif isinstance(field, forms.ModelMultipleChoiceField):
                data[name] = list(value or [])
            else:
                data[name] = value if value is not None else ''
        data['_save'] = 'Save'
        return data

    def state(self):
        self.target.refresh_from_db()
        return (self.target.is_active, self.target.session_version, self.target.first_name,
                AuditLog.objects.filter(event_type='user.activation_changed').count())

    def test_stale_original_checkbox_rejected_both_directions_with_or_without_confirmation(self):
        for original in (True, False):
            for confirmed in (False, True):
                with self.subTest(original=original, confirmed=confirmed):
                    change_account_status(self.actor, self.target.pk, original)
                    data = self.opened_form_data()
                    change_account_status(self.actor, self.target.pk, not original)
                    before = self.state()
                    data['first_name'] = 'stale unrelated edit'
                    if confirmed:
                        data['confirm_account_status'] = 'on'
                    response = self.client.post(self.url, data)
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(self.state(), before)

    def test_status_cycle_and_explicit_stale_transition_rejected(self):
        for requested_change in (False, True):
            data = self.opened_form_data()
            change_account_status(self.actor, self.target.pk, False)
            change_account_status(self.actor, self.target.pk, True)
            if requested_change:
                data.pop('is_active', None)
                data['confirm_account_status'] = 'on'
            before = self.state()
            self.assertEqual(self.client.post(self.url, data).status_code, 403)
            self.assertEqual(self.state(), before)

    def test_fresh_transitions_and_unrelated_edit(self):
        for active in (False, True):
            data = self.opened_form_data()
            if active:
                data['is_active'] = 'on'
            else:
                data.pop('is_active', None)
            data['confirm_account_status'] = 'on'
            self.assertEqual(self.client.post(self.url, data).status_code, 302)
            self.assertEqual(self.state()[0], active)
        before = self.state()
        data = self.opened_form_data(); data['first_name'] = 'fresh edit'
        self.assertEqual(self.client.post(self.url, data).status_code, 302)
        after = self.state()
        self.assertEqual(after[:2], before[:2])
        self.assertEqual(after[2], 'fresh edit')
        self.assertEqual(after[3], before[3])

    def test_fresh_transition_requires_confirmation(self):
        data = self.opened_form_data(); data.pop('is_active', None)
        before = self.state()
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('confirm_account_status', response.context['adminform'].form.errors)
        self.assertEqual(self.state(), before)

    def test_invalid_snapshots_rejected_in_real_admin(self):
        from django.core import signing
        data = self.opened_form_data()
        pk, baseline = signing.loads(data['security_state'], salt='admin-security-state')
        self.assertEqual(set(baseline), {'is_active', 'session_version', 'is_admin', 'is_superuser', 'is_staff'})
        self.assertIs(type(baseline['is_active']), bool)
        self.assertIs(type(baseline['session_version']), int)
        with patch('django.core.signing.time.time', return_value=1):
            expired = signing.dumps([pk, baseline], salt='admin-security-state')
        bad_snapshots = ['', data['security_state'] + 'tampered', expired,
            signing.dumps([pk + 1, baseline], salt='admin-security-state'),
            signing.dumps([True, baseline], salt='admin-security-state'),
            signing.dumps([pk, {**baseline, 'is_active': 1}], salt='admin-security-state'),
            signing.dumps([pk, {**baseline, 'session_version': True}], salt='admin-security-state'),
            signing.dumps([pk, {**baseline, 'session_version': -1}], salt='admin-security-state'),
            signing.dumps([pk, {**baseline, 'extra': False}], salt='admin-security-state'),
            signing.dumps([pk, ['is_active']], salt='admin-security-state'),
            signing.dumps({'pk': pk}, salt='admin-security-state')]
        before = self.state()
        for token in bad_snapshots:
            with self.subTest(kind=bad_snapshots.index(token)):
                payload = dict(data, security_state=token, first_name='must not save')
                response = self.client.post(self.url, payload)
                self.assertEqual(response.status_code, 200)
                self.assertIn('security_state', response.context['adminform'].form.errors)
                self.assertEqual(self.state(), before)
