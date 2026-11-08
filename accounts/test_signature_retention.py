from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch
from django.test import TestCase, override_settings, Client
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, models
from django.urls import reverse
from .models import User, RetainedSignature
from .signatures import signature_valid
from .signature_replacement import replace_signature, version
from .test_onboarding import png


class SignatureRetentionTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory(); self.addCleanup(directory.cleanup)
        override = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
        override.enable(); self.addCleanup(override.disable)
        self.user = User.objects.create_user(username='retention')
        self.user.signature_image.save('initial.png', ContentFile(png()))
        self.assertTrue(signature_valid(self.user))
        self.old = self.user.signature_image.name
        self.token = version(self.user)
        self.client.force_login(self.user)

    def upload(self):
        return SimpleUploadedFile('new.png', png((100, 50)))

    def test_replace_retains_and_stale_rejected(self):
        keys = (self.user.private_key, self.user.public_key)
        replace_signature(self.user, self.upload(), self.token)
        row = RetainedSignature.objects.get()
        self.assertEqual(row.owner_id, self.user.pk)
        self.assertEqual(row.owner_identifier, str(self.user.pk))
        self.assertEqual(row.storage_identifier, self.old)
        self.assertGreaterEqual((row.eligible_at-row.superseded_at).days, 90)
        self.assertTrue(row.historical_hold)
        self.assertTrue(self.user.signature_image.storage.exists(self.old))
        self.user.refresh_from_db()
        self.assertTrue(signature_valid(self.user))
        self.assertNotEqual(self.user.signature_image.name, self.old)
        self.assertEqual((self.user.private_key, self.user.public_key), keys)
        with self.assertRaises(ValidationError):
            replace_signature(self.user, self.upload(), self.token)
        self.assertEqual(RetainedSignature.objects.count(), 1)

    def test_supported_bypasses_blocked(self):
        with self.assertRaises(PermissionDenied):
            self.user.signature_image.save('replace.png', ContentFile(png()))
        with self.assertRaises(PermissionDenied):
            User.objects.filter(pk=self.user.pk).update(signature_image='elsewhere.png')
        self.user.signature_image = self.upload()
        with self.assertRaises(PermissionDenied):
            self.user.save()
        with self.assertRaises(PermissionDenied):
            User.objects.bulk_update([self.user], ['signature_image'])

    def test_failures_never_delete_files_or_commit_ledger(self):
        from pathlib import Path
        for target, error in [('accounts.signatures.SignatureStorage.save', OSError()),
                              ('accounts.signature_replacement.record', IntegrityError())]:
            before = len(list(Path(self.user.signature_image.storage.location).rglob('*.png')))
            with patch(target, side_effect=error), self.assertRaises(type(error)):
                replace_signature(self.user, self.upload(), self.token)
            self.user.refresh_from_db()
            self.assertEqual(self.user.signature_image.name, self.old)
            self.assertTrue(self.user.signature_image.storage.exists(self.old))
            self.assertFalse(RetainedSignature.objects.exists())
            after = len(list(Path(self.user.signature_image.storage.location).rglob('*.png')))
            self.assertEqual(after, before + (1 if isinstance(error, IntegrityError) else 0))

    @override_settings(SIGNATURE_RETENTION_DAYS=89)
    def test_retention_floor(self):
        with self.assertRaises(ValidationError):
            replace_signature(self.user, self.upload(), self.token)

    def test_confirmation_authorization_and_preview(self):
        url = reverse('replace_account_signature')
        response = self.client.post(url, {'version': self.token, 'signature': self.upload()})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(url, {'version': self.token, 'signature': self.upload(), 'confirm': 'on', 'owner': 999})
        self.assertRedirects(response, reverse('account_settings'))
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 200)
        admin = User.objects.create_user(username='global', is_admin=True)
        self.client.force_login(admin)
        self.assertNotContains(self.client.get(reverse('account_settings')), 'Replace signature')
        self.assertEqual(self.client.post(url).status_code, 403)
        incomplete = User.objects.create_user(username='incomplete')
        self.client.force_login(incomplete)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.post(url).status_code, 302)
        client = Client(enforce_csrf_checks=True); client.force_login(self.user)
        self.assertEqual(client.post(url).status_code, 403)

    def test_command_and_owner_set_null(self):
        replace_signature(self.user, self.upload(), self.token)
        before = list(RetainedSignature.objects.values())
        out = StringIO(); call_command('inspect_signature_retention', limit=1, stdout=out)
        self.assertNotIn(self.old, out.getvalue())
        self.assertIn('Physical deletion disabled', out.getvalue())
        self.assertEqual(before, list(RetainedSignature.objects.values()))
        identifier = str(self.user.pk)
        self.user.delete()
        row = RetainedSignature.objects.get()
        self.assertIsNone(row.owner_id)
        self.assertEqual(row.owner_identifier, identifier)

    def test_admin_has_no_signature_upload(self):
        from .admin import SignatureUserChangeForm
        self.assertNotIn('signature_image', SignatureUserChangeForm(instance=self.user).fields)

    def test_invalid_upload_and_cross_account_token(self):
        for data in (b'bad', b'x' * 2097153, png((4097, 1))):
            with self.assertRaises(ValidationError):
                replace_signature(self.user, SimpleUploadedFile('bad.png', data), self.token)
        other = User.objects.create_user(username='other')
        other.signature_image.save('initial.png', ContentFile(png()))
        self.assertTrue(signature_valid(other))
        with self.assertRaises(ValidationError):
            replace_signature(other, self.upload(), self.token)
        self.assertFalse(RetainedSignature.objects.exists())

    def test_legacy_reference_retained_and_recovery(self):
        from django.conf import settings
        from django.core.files.storage import FileSystemStorage
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory, override_settings(MEDIA_ROOT=directory):
            name = FileSystemStorage(location=directory).save('signatures/legacy.png', ContentFile(png()))
            models.QuerySet.update(User.objects.filter(pk=self.user.pk), signature_image=name)
            self.user.refresh_from_db(); self.assertTrue(signature_valid(self.user))
            replace_signature(self.user, self.upload(), version(self.user))
            row = RetainedSignature.objects.get()
            self.assertEqual(row.storage_namespace, 'legacy')
            self.assertEqual(row.storage_identifier, name)
            self.assertTrue(FileSystemStorage(location=directory).exists(name))
        models.QuerySet.update(User.objects.filter(pk=self.user.pk), signature_image='normalized/missing.png')
        response = self.client.post(reverse('onboarding'), {'signature': self.upload()})
        self.assertRedirects(response, reverse('central_dashboard'))
        self.assertTrue(RetainedSignature.objects.filter(state='unresolved', source='onboarding').exists())

    def test_command_bounds_and_deletion_disabled(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command('inspect_signature_retention', limit=1001, stdout=StringIO())
        with self.assertRaises(PermissionDenied):
            self.user.signature_image.storage.delete(self.old)
