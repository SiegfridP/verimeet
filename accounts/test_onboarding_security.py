"""Security edge cases using isolated storage and the real onboarding gate."""
from datetime import timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch
from django.http import HttpResponse
from django.db import models
from pathlib import Path
from django.test import TestCase, RequestFactory, override_settings
from django.urls import include, path, resolve, reverse
from django.utils import timezone
from allauth.account.models import EmailAddress
from allauth.account import views as auth_views
from . import views
from .models import User, Invitation, Department
from .signatures import SignatureStorage, signature_valid, LIMIT
from .test_onboarding import png


def protected(request):
    return HttpResponse('Executed protected action')


urlpatterns = [
    path('collision/', protected, name='account_login'),
    path('unnamed/', protected),
    path('namespaced/', include(([path('collision/', protected, name='onboarding'),
                                 path('logout/', auth_views.logout, name='logout')], 'test'))),
    path('', include('core.urls')),
]


class OnboardingSecurityTests(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        override = override_settings(PRIVATE_SIGNATURE_ROOT=self.directory.name,
                                     MEDIA_ROOT=self.directory.name + '/legacy')
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username='security-user')
        self.client.force_login(self.user)

    def stored(self, data):
        from django.core.files.base import ContentFile
        from django.core.files.storage import FileSystemStorage
        # Seed an existing unnormalized asset, not a new supported upload.
        name = FileSystemStorage(location=self.directory.name).save('normalized/test.png', ContentFile(data))
        # Historical/corrupted-state fixture only: normal replacement must use
        # the service and retention ledger. These tests exercise stale readers.
        models.QuerySet.update(User.objects.filter(pk=self.user.pk), signature_image=name)
        self.user.refresh_from_db()
        return name

    def test_generic_storage_urls_are_unavailable_and_admin_widget_is_safe(self):
        from .admin import CustomUserAdmin
        from django.contrib.admin.sites import AdminSite
        self.stored(png())
        for name in ('normalized/test.png', 'signatures/other.png'):
            with self.assertRaises(NotImplementedError):
                SignatureStorage().url(name)
        admin = CustomUserAdmin(User, AdminSite())
        field = admin.formfield_for_dbfield(User._meta.get_field('signature_image'), request=RequestFactory().get('/'))
        html = field.widget.render('signature_image', self.user.signature_image)
        self.assertNotIn('href=', html)
        self.assertNotIn('normalized/', html)

    def test_validation_no_rewrite_no_repeat_decode_or_db_write(self):
        name = self.stored(png())
        storage = self.user.signature_image.storage
        with patch.object(storage, 'save', side_effect=AssertionError('must not rewrite')):
            self.assertTrue(signature_valid(self.user))
        with self.assertNumQueries(1), patch('accounts.signatures.decode_png') as decode:
            self.assertTrue(signature_valid(self.user))
            decode.assert_not_called()
        self.assertEqual(self.user.signature_image.name, name)

    def test_preview_serves_one_validated_snapshot_and_success_is_accurate(self):
        self.stored(png((100, 50)))  # Valid legacy-sized input is not normalized on GET.
        self.assertTrue(signature_valid(self.user))
        storage = self.user.signature_image.storage
        with patch.object(storage, 'open', wraps=storage.open) as opened:
            response = self.client.get(reverse('signature_preview'))
        self.assertEqual(response.content, png((100, 50)))
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(response['Cache-Control'], 'private, no-store')
        response = self.client.post(reverse('onboarding'), follow=True)
        self.assertContains(response, 'Account onboarding complete.')
        self.assertNotContains(response, 'Signature saved and automatically formatted')

    def test_stale_validator_cannot_overwrite_newer_cache(self):
        name = self.stored(png())
        self.assertTrue(signature_valid(self.user))
        stale = User.objects.get(pk=self.user.pk)
        with self.user.signature_image.storage.open(name, 'wb') as stream:
            stream.write(png((35, 15)))
        self.assertTrue(signature_valid(self.user))
        winner = self.user.signature_validation_hash
        self.assertFalse(signature_valid(stale))
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_validation_hash, winner)
        self.assertTrue(self.user.signature_validated)

    def test_cached_stale_user_rejected_after_file_reference_replacement(self):
        self.stored(png())
        self.assertTrue(signature_valid(self.user))
        stale = User.objects.get(pk=self.user.pk)
        replacement = self.stored(png((40, 20)))
        self.assertTrue(signature_valid(self.user))
        with patch('accounts.signatures.decode_png') as decode:
            self.assertFalse(signature_valid(stale))
            decode.assert_not_called()
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, replacement)
        self.assertTrue(signature_valid(self.user))

    def test_cached_stale_user_rejected_after_validation_state_change(self):
        self.stored(png())
        self.assertTrue(signature_valid(self.user))
        original_hash = self.user.signature_validation_hash
        for updates in ({'signature_validated': False},
                        {'signature_validated': True, 'signature_validation_hash': '0' * 64},
                        {'signature_image': 'normalized/missing.png'}):
            # Deliberately simulate corrupt or concurrently replaced state.
            models.QuerySet.update(User.objects.filter(pk=self.user.pk), **updates)
            with patch('accounts.signatures.decode_png') as decode:
                self.assertFalse(signature_valid(self.user))
                decode.assert_not_called()
            models.QuerySet.update(User.objects.filter(pk=self.user.pk), signature_image=self.user.signature_image.name,
                signature_validated=True, signature_validation_hash=original_hash)
        self.assertTrue(signature_valid(self.user))

    def changed_during_form_construction(self, change):
        from .forms import OnboardingForm
        calls = 0

        def build(*args, **kwargs):
            nonlocal calls
            form = OnboardingForm(*args, **kwargs)
            calls += 1
            if calls == 1:
                change()
            return form

        return patch('accounts.forms.OnboardingForm', side_effect=build)

    def test_signature_becomes_invalid_before_transaction_requires_upload(self):
        self.stored(png())
        self.assertTrue(signature_valid(self.user))
        # Simulate a disappeared legacy reference, not an authorized replacement.
        change = lambda: models.QuerySet.update(User.objects.filter(pk=self.user.pk),
                                                signature_image='normalized/missing.png')
        with self.changed_during_form_construction(change):
            response = self.client.post(reverse('onboarding'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('signature', response.context['form'].errors)
        self.assertFalse(response.context['signature_ready'])
        self.assertNotContains(response, 'Could not save onboarding')
        self.user.refresh_from_db()
        self.assertFalse(signature_valid(self.user))

    def test_concurrent_valid_signature_is_preserved_without_replacement(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        with self.changed_during_form_construction(lambda: self.stored(png((100, 50)))):
            response = self.client.post(reverse('onboarding'), {
                'signature': SimpleUploadedFile('bad.png', b'not PNG')})
        self.assertRedirects(response, reverse('central_dashboard'))
        self.user.refresh_from_db()
        self.assertTrue(signature_valid(self.user))
        with self.user.signature_image.open('rb') as stream:
            self.assertEqual(stream.read(), png((100, 50)))

    def test_new_username_requirement_gets_specific_validation_error(self):
        self.stored(png())
        change = lambda: User.objects.filter(pk=self.user.pk).update(username_confirmation_required=True)
        with self.changed_during_form_construction(change):
            response = self.client.post(reverse('onboarding'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('username', response.context['form'].errors)
        self.assertNotContains(response, 'Could not save onboarding')
        self.user.refresh_from_db()
        self.assertTrue(self.user.username_confirmation_required)

    def test_concurrently_confirmed_username_is_not_overwritten(self):
        self.stored(png())
        User.objects.filter(pk=self.user.pk).update(username_confirmation_required=True)
        change = lambda: User.objects.filter(pk=self.user.pk).update(
            username_confirmation_required=False, username='concurrent-choice')
        with self.changed_during_form_construction(change):
            response = self.client.post(reverse('onboarding'), {'username': 'stale-choice'})
        self.assertRedirects(response, reverse('central_dashboard'))
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'concurrent-choice')
        self.assertFalse(self.user.username_confirmation_required)

    def test_png_dimension_error_is_ascii_safe(self):
        from django.core.exceptions import ValidationError
        from .signatures import decode_png
        with self.assertRaisesMessage(ValidationError, '4096 x 4096 pixels'):
            decode_png(png((4097, 1)))

    def test_signature_invalidated_during_save_refreshes_upload_requirement(self):
        name = self.stored(png())
        self.assertTrue(signature_valid(self.user))
        original_save = User.save

        def invalidate(user, *args, **kwargs):
            original_save(user, *args, **kwargs)
            if user.pk == self.user.pk:
                with user.signature_image.storage.open(name, 'wb') as stream:
                    stream.write(b'invalid during save')

        with patch.object(User, 'save', invalidate):
            response = self.client.post(reverse('onboarding'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Could not save onboarding')
        self.assertIn('signature', response.context['form'].fields)
        self.assertFalse(response.context['signature_ready'])
        self.user.refresh_from_db()
        self.assertFalse(signature_valid(self.user))

    def test_invalid_oversized_missing_and_unexpected_storage_errors(self):
        name = self.stored(png())
        self.assertTrue(signature_valid(self.user))
        for data in (b'broken', b'x' * (LIMIT + 1)):
            with self.user.signature_image.storage.open(name, 'wb') as stream:
                stream.write(data)
            self.assertFalse(signature_valid(self.user))
        # Simulate an externally missing file in isolated test storage. The
        # application storage API intentionally prohibits physical deletion.
        (Path(self.directory.name) / name).unlink()
        self.assertFalse(signature_valid(self.user))
        with patch.object(self.user.signature_image.storage, 'open', side_effect=RuntimeError('backend unavailable')):
            self.assertFalse(signature_valid(self.user))

    @override_settings(ROOT_URLCONF=__name__)
    def test_unnamed_namespaced_and_colliding_routes_are_gated(self):
        for url in ('/collision/', '/unnamed/', '/namespaced/collision/'):
            self.assertRedirects(self.client.get(url), reverse('onboarding'))
            self.assertEqual(self.client.post(url).status_code, 403)
        self.assertEqual(self.client.get('/namespaced/logout/').status_code, 200)

    def test_authentication_exemptions_use_actual_callables(self):
        from .middleware import OnboardingMiddleware
        middleware = OnboardingMiddleware(lambda request: HttpResponse())
        urls = ['/accounts/auth/login/', '/accounts/auth/logout/', '/accounts/auth/signup/',
                '/accounts/auth/email/', '/accounts/auth/confirm-email/',
                '/accounts/auth/confirm-email/test/', '/accounts/auth/google/login/',
                '/accounts/auth/google/login/callback/', '/accounts/auth/google/login/token/',
                '/accounts/onboarding/', '/accounts/signature/preview/', '/meetings/verify/']
        for url in urls:
            with self.subTest(url=url):
                match = resolve(url)
                request = RequestFactory().get(url)
                request.user, request.resolver_match = self.user, match
                self.assertIsNone(middleware.process_view(request, match.func, (), match.kwargs))
        self.assertContains(self.client.get(reverse('onboarding')), 'Complete your account')
        self.assertNotEqual(self.client.get('/meetings/verify/').status_code, 302)

    def test_legacy_media_blocked_without_route_and_for_anonymous_users(self):
        for logged_in in (True, False):
            if not logged_in:
                self.client.logout()
            for url in ('/media/signatures/missing.png', '/media/SIGNATURES/missing.png',
                        '/media/other/../signatures/missing.png', '/media/signatures/',
                        '/media/signatures./missing.png'):
                self.assertEqual(self.client.get(url).status_code, 403)

    def invitation(self):
        department = Department.objects.create(name='Security invitations')
        invitation = Invitation.objects.create(department=department, inviter=self.user, email='owner@example.com')
        EmailAddress.objects.create(user=self.user, email=invitation.email, verified=True)
        return invitation

    def test_invitation_context_invalid_states_and_account_binding(self):
        from .views import onboarding_destination
        invitation = self.invitation()
        target = reverse('accept_invitation', args=[invitation.token])
        for marker in ('onboarding_invitation', 'invite_verification_intent'):
            def destination(account_id=None):
                request = RequestFactory().get('/')
                request.user = self.user
                request.session = {'pending_invite_token': invitation.token,
                                   marker: [invitation.token, account_id or self.user.pk]}
                return onboarding_destination(request)
            self.assertEqual(destination(), target)
            self.assertEqual(destination(self.user.pk + 100), reverse('central_dashboard'))
            EmailAddress.objects.filter(user=self.user).update(verified=False)
            self.assertEqual(destination(), reverse('central_dashboard'))
            EmailAddress.objects.filter(user=self.user).update(verified=True)
            for fields in ({'expires_at': timezone.now() - timedelta(seconds=1)}, {'accepted': True}):
                Invitation.objects.filter(pk=invitation.pk).update(**fields)
                self.assertEqual(destination(), reverse('central_dashboard'))
                Invitation.objects.filter(pk=invitation.pk).update(accepted=False, expires_at=timezone.now()+timedelta(days=1))
            Department.objects.filter(pk=invitation.department_id).update(is_active=False)
            self.assertEqual(destination(), reverse('central_dashboard'))
            Department.objects.filter(pk=invitation.department_id).update(is_active=True)
        invitation.delete()  # Replacement revokes the old token by deleting its row.
        self.assertEqual(destination(), reverse('central_dashboard'))

    def test_direct_invitation_gate_keeps_separate_account_bound_intent(self):
        invitation = self.invitation()
        target = reverse('accept_invitation', args=[invitation.token])
        self.assertRedirects(self.client.get(target), reverse('onboarding'))
        self.assertNotIn('invite_verification_intent', self.client.session)
        self.assertEqual(self.client.session['onboarding_invitation'], [invitation.token, self.user.pk])
        self.assertEqual(self.client.post(target).status_code, 403)
        invitation.refresh_from_db()
        self.assertFalse(invitation.accepted)

    def test_google_only_new_signup_requires_confirmation(self):
        from allauth.socialaccount.models import SocialAccount, SocialLogin
        from .adapter import OnboardingSocialAdapter
        for provider, existing, process in [('google', False, 'login'), ('google', True, 'login'),
                                             ('google', False, 'connect'), ('other', False, 'login')]:
            user = self.user if existing else User(username='suggestion')
            social = SocialLogin(user=user, account=SocialAccount(provider=provider, uid='example'))
            social.state = {'process': process}
            with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.save_user', return_value=user) as parent:
                result = OnboardingSocialAdapter().save_user(RequestFactory().get('/'), social)
            parent.assert_called_once()
            self.assertIs(result, user)
            self.assertEqual(user.username_confirmation_required, provider == 'google' and not existing and process != 'connect')
