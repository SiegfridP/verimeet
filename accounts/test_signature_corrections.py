from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from django.test import TestCase, override_settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.db import models, DatabaseError, IntegrityError, OperationalError
from django.urls import reverse
from .models import User, RetainedSignature
from .signature_replacement import _recover_onboarding_signature, replace_signature
from .signatures import signature_valid
from . import test_signature_retention as retention_tests
from .test_onboarding import png


class SignatureCorrectionTests(TestCase):
    setUp = retention_tests.SignatureRetentionTests.setUp
    upload = retention_tests.SignatureRetentionTests.upload

    def seed_reference(self, name):
        # Simulate pre-existing/externally changed references, outside upload APIs.
        models.QuerySet.update(User.objects.filter(pk=self.user.pk), signature_image=name,
                               signature_validation_hash='', signature_validated=False)
        self.user.refresh_from_db()

    def test_missing_recovery_is_valid_and_retained(self):
        self.seed_reference('normalized/missing.png')
        new = _recover_onboarding_signature(self.user, self.upload())
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, new)
        self.assertTrue(signature_valid(self.user))
        row = RetainedSignature.objects.get()
        self.assertEqual(row.storage_identifier, 'normalized/missing.png')
        self.assertEqual(row.state, 'unresolved')
        self.assertEqual(row.content_sha256, '')

    def test_corrupt_legacy_recovery_preserves_file_and_metadata(self):
        with TemporaryDirectory() as directory, override_settings(MEDIA_ROOT=directory):
            storage = FileSystemStorage(location=directory)
            name = storage.save('signatures/corrupt.png', ContentFile(b'corrupt PNG'))
            self.seed_reference(name)
            _recover_onboarding_signature(self.user, self.upload())
            row = RetainedSignature.objects.get()
            self.assertEqual(row.storage_namespace, 'legacy')
            self.assertEqual(row.storage_identifier, name)
            self.assertEqual(row.content_sha256, sha256(b'corrupt PNG').hexdigest())
            with storage.open(name, 'rb') as stream:
                self.assertEqual(stream.read(), b'corrupt PNG')
            self.user.refresh_from_db()
            self.assertTrue(signature_valid(self.user))

    def test_stale_missing_instance_cannot_recover_over_newer_signature(self):
        self.seed_reference('normalized/missing.png')
        stale = User.objects.get(pk=self.user.pk)
        self.seed_reference(self.old)
        self.assertTrue(signature_valid(self.user))
        with self.assertRaises(ValidationError):
            _recover_onboarding_signature(stale, self.upload())
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, self.old)
        self.assertFalse(RetainedSignature.objects.exists())

    def test_recovery_audit_failure_rolls_back_independently(self):
        self.seed_reference('normalized/missing.png')
        with patch('accounts.signature_replacement.record', side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                _recover_onboarding_signature(self.user, self.upload())
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, 'normalized/missing.png')
        self.assertFalse(RetainedSignature.objects.exists())
        self.assertEqual(len(list(Path(self.user.signature_image.storage.location).rglob('*.png'))), 2)

    def test_later_onboarding_save_failure_rolls_back_recovery(self):
        self.seed_reference('normalized/missing.png')
        with patch('accounts.views.User.save', side_effect=IntegrityError):
            response = self.client.post(reverse('onboarding'), {'signature': self.upload()})
        self.assertContains(response, 'Could not save onboarding')
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, 'normalized/missing.png')
        self.assertFalse(RetainedSignature.objects.exists())
        self.assertEqual(len(list(Path(self.user.signature_image.storage.location).rglob('*.png'))), 2)

    def test_recovery_followup_saves_only_non_signature_onboarding_fields(self):
        self.seed_reference('normalized/missing.png')
        User.objects.filter(pk=self.user.pk).update(username_confirmation_required=True)
        original_save = User.save
        saved_fields = []

        def save(instance, *args, **kwargs):
            saved_fields.append(set(kwargs.get('update_fields', [])))
            return original_save(instance, *args, **kwargs)

        with patch.object(User, 'save', save):
            response = self.client.post(reverse('onboarding'), {
                'signature': self.upload(), 'username': 'confirmed-username'})
        self.assertRedirects(response, reverse('central_dashboard'))
        self.assertEqual(saved_fields, [{'username', 'username_confirmation_required'}])
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'confirmed-username')
        self.assertFalse(self.user.username_confirmation_required)
        self.assertTrue(signature_valid(self.user))
        self.assertEqual(RetainedSignature.objects.get().storage_identifier, 'normalized/missing.png')

    def test_initial_onboarding_save_still_persists_signature_fields(self):
        initial = User.objects.create_user(username='initial-fields')
        self.client.force_login(initial)
        original_save = User.save
        saved_fields = []

        def save(instance, *args, **kwargs):
            saved_fields.append(set(kwargs.get('update_fields', [])))
            return original_save(instance, *args, **kwargs)

        with patch.object(User, 'save', save):
            response = self.client.post(reverse('onboarding'), {'signature': self.upload()})
        self.assertRedirects(response, reverse('central_dashboard'))
        self.assertEqual(saved_fields, [{'username', 'username_confirmation_required',
            'signature_image', 'signature_validation_hash', 'signature_validated'}])
        initial.refresh_from_db()
        self.assertTrue(signature_valid(initial))
        self.assertFalse(RetainedSignature.objects.exists())

    def test_corrupt_private_recovery_does_not_rewrite_old_bytes(self):
        storage = FileSystemStorage(location=self.user.signature_image.storage.location)
        name = storage.save('normalized/corrupt.png', ContentFile(b'corrupt private PNG'))
        self.seed_reference(name)
        _recover_onboarding_signature(self.user, self.upload())
        self.user.refresh_from_db()
        self.assertTrue(signature_valid(self.user))
        row = RetainedSignature.objects.get()
        self.assertEqual(row.storage_namespace, 'private')
        self.assertEqual(row.storage_identifier, name)
        self.assertEqual(row.file_size, len(b'corrupt private PNG'))
        with storage.open(name, 'rb') as stream:
            self.assertEqual(stream.read(), b'corrupt private PNG')

    def test_only_sqlite_contention_is_retryable(self):
        url = reverse('replace_account_signature')
        for error in (OperationalError('database is locked'), OperationalError('database is busy'), OSError('private path')):
            with patch('accounts.signature_replacement.record', side_effect=error):
                response = self.client.post(url, {'signature': self.upload(), 'version': self.token, 'confirm': 'on'})
            self.assertEqual(response.status_code, 400)
            self.assertNotContains(response, 'private path', status_code=400)
            self.user.refresh_from_db()
            self.assertEqual(self.user.signature_image.name, self.old)
            self.assertFalse(RetainedSignature.objects.exists())
        for error in (OperationalError('disk I/O error'), DatabaseError('unexpected failure')):
            with patch('accounts.signature_replacement.record', side_effect=error):
                with self.assertRaises(type(error)):
                    self.client.post(url, {'signature': self.upload(), 'version': self.token, 'confirm': 'on'})
            self.user.refresh_from_db()
            self.assertEqual(self.user.signature_image.name, self.old)
            self.assertFalse(RetainedSignature.objects.exists())

    def test_model_guards_initial_upload_and_unrelated_updates(self):
        initial = User.objects.create_user(username='initial')
        stale = User.objects.get(pk=initial.pk)
        initial.signature_image.save('initial.png', ContentFile(png()))
        stale.signature_image = self.upload()
        with self.assertRaises(PermissionDenied):
            stale.save()
        with self.assertRaises(PermissionDenied):
            User.objects.filter(pk=stale.pk).update(signature_image='unvalidated.png')
        empty = User.objects.create_user(username='empty')
        with self.assertRaises(PermissionDenied):
            User.objects.filter(pk=empty.pk).update(signature_image=initial.signature_image.name)
        initial.username = 'updated'
        initial.save(update_fields=['username'])
        self.assertEqual(User.objects.get(pk=initial.pk).username, 'updated')
        with self.assertRaises(PermissionDenied):
            User.objects.bulk_create([User(username='conflict')], update_conflicts=True,
                                    update_fields=['signature_image'], unique_fields=['username'])
        # Intentional internal update still retains the old active reference.
        replace_signature(self.user, self.upload(), self.token)
        self.assertEqual(RetainedSignature.objects.get().storage_identifier, self.old)
